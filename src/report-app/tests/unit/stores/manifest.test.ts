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
import { gzipSync } from 'node:zlib'
import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { decodeEmbeddedManifest, useManifestStore } from '@/stores/manifest'
import type { ReportLoadReporter } from '@/services/reportStartup'
import type { Manifest, RunIdentity, RunResult, TimingReference } from '@/types/manifest'
import { ERROR_CLUSTER_INPUT_LIMIT } from '@/utils/errorEntries'

const SAMPLE_MANIFEST: Manifest = {
  version: '1.0',
  generated_at: '2026-03-18T14:30:00Z',
  tool_version: '2.1.0',
  tool_config: { collection_level: 'L2', execution_mode: 'RemoteClient', baseboard: 'HGX_H100' },
  duts: [
    {
      id: 'DUT_1',
      baseboard: 'HGX_H100',
      node_type: 'Compute',
      bmc_ip: '10.0.0.1',
      collector_groups: [],
      status_summary: { success: 10, error: 2, partial: 1, skipped: 0, not_ran: 0 },
      overall_status: 'error',
      execution_time: 120.5,
      log_size: 52428800,
      system_info: { model: 'DGXH100', part_number: '123-456', serial_number: 'ABC789', firmware: [] },
    },
  ],
  collector_catalog: [],
  timing: { total_duration: 120.5, component_timing: { tool_init: null, config_load: null, dut_init: null, preflight: null, collection: null, report_generation: null, metadata_write: null, cleanup: null }, per_dut: [], per_service: [] },
  file_index: [
    { path: 'DUT_1/redfish/Systems.json', size: 1024, type: 'json', collector_id: 'R1', dut_id: 'DUT_1', collector_group: 'redfish', collector_name: 'Systems' },
    { path: 'DUT_1/host/dmesg.log', size: 5242880, type: 'log', collector_id: 'H1', dut_id: 'DUT_1', collector_group: 'host', collector_name: 'dmesg' },
  ],
  errors: [
    { dut_id: 'DUT_1', collector_id: 'R5', collector_name: 'Thermal', collector_group: 'redfish', message: 'Connection timeout', timestamp: null },
  ],
  preflight: { per_dut: [] },
  run_result: null,
  collection_summary: {
    total_duts: 1,
    total_collectors_executed: 13,
    total_collectors_in_catalog: 50,
    total_collectors_filtered_out: 37,
    total_log_size: 52428800,
    total_runtime: 120.5,
    overall_collection_pct: 76.9,
    runtime_status: null,
    collection_status: null,
    collector_counts: null,
    run_result: null,
    status_counts: { success: 10, error: 2, partial: 1, skipped: 0, not_ran: 0 },
  },
}

const SUCCESS_RUN_RESULT: RunResult = {
  schema_version: '1.0',
  mode: 'collection',
  runtime_status: 'success',
  collection_status: 'success',
  collector_counts: {
    total_collectors: 1,
    pending_collectors: 0,
    running_collectors: 0,
    completed_collectors: 1,
    degraded_collectors: 0,
    partial_collectors: 0,
    failed_collectors: 0,
    skipped_collectors: 0,
    cancelled_collectors: 0,
    baseboard_excluded: 0,
    capability_excluded: 0,
    config_excluded: 0,
  },
  terminal_snapshot_committed: true,
  explicit_domain_failure: false,
  dut_roster: ['DUT_1'],
  affected_duts: [],
  reasons: [],
}

const RUN_IDENTITY: RunIdentity = sealIdentityFixture({
  schema_version: '1.1',
  tool: {
    version: '2.2.0',
    build_hash: '86aeb7a',
    source_mode: 'source',
    source_revision: '1'.repeat(40),
    build_timestamp_utc: '2026-08-07T12:34:56Z',
  },
  catalog: {
    name: 'Telemetry_Catalog_v2.2.xlsx',
    version: '2.2',
    sha256: '2'.repeat(64),
    size_bytes: 1024,
    binding: 'manifest_bound',
  },
  effective_config_sha256: '3'.repeat(64),
  invocation: {
    resolved_level: 'L2',
    resolved_profile: 'level',
    resolved_plan_sha256: '6'.repeat(64),
    invocation_sha256: '',
  },
  output: {
    mode: 'configured_generated',
    caller_relation: 'absent',
    caller_path: {
      path_sha256: null,
      version_alignment: 'not_declared',
      level_alignment: 'not_declared',
      profile_alignment: 'not_declared',
    },
    resolved_path: {
      path_sha256: '7'.repeat(64),
      version_alignment: 'aligned',
      level_alignment: 'aligned',
      profile_alignment: 'aligned',
    },
    generated_path: {
      path_sha256: '7'.repeat(64),
      version_alignment: 'aligned',
      level_alignment: 'aligned',
      profile_alignment: 'aligned',
    },
  },
  identity_sha256: '',
})

const IDENTITY_RUN_RESULT: RunResult = {
  ...structuredClone(SUCCESS_RUN_RESULT),
  schema_version: '1.1',
  run_identity: RUN_IDENTITY,
}

function canonicalFixture(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalFixture).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record).sort().map(
    key => `${JSON.stringify(key)}:${canonicalFixture(record[key])}`,
  ).join(',')}}`
}

function fixtureDigest(value: unknown): string {
  return createHash('sha256').update(canonicalFixture(value)).digest('hex')
}

function sealIdentityFixture(document: RunIdentity): RunIdentity {
  const identity = structuredClone(document)
  const invocationMaterial = {
    schema_version: identity.schema_version,
    tool: identity.tool,
    catalog: identity.catalog,
    effective_config_sha256: identity.effective_config_sha256,
    invocation: {
      resolved_level: identity.invocation.resolved_level,
      resolved_profile: identity.invocation.resolved_profile,
      resolved_plan_sha256: identity.invocation.resolved_plan_sha256,
    },
    output: identity.output,
  }
  identity.invocation.invocation_sha256 = fixtureDigest(invocationMaterial)
  identity.identity_sha256 = fixtureDigest({
    ...invocationMaterial,
    invocation: identity.invocation,
  })
  return identity
}

function identityWithOutput(output: RunIdentity['output']): RunIdentity {
  return sealIdentityFixture({
    ...structuredClone(RUN_IDENTITY),
    output: structuredClone(output),
  })
}

function outputFixture(
  mode: RunIdentity['output']['mode'],
  callerRelation: RunIdentity['output']['caller_relation'],
  callerDigest: string | null,
  generatedDigest: string | null,
): RunIdentity['output'] {
  const path = (digest: string | null) => ({
    path_sha256: digest,
    version_alignment: digest === null ? 'not_declared' as const : 'aligned' as const,
    level_alignment: digest === null ? 'not_declared' as const : 'aligned' as const,
    profile_alignment: digest === null ? 'not_declared' as const : 'aligned' as const,
  })
  return {
    mode,
    caller_relation: callerRelation,
    caller_path: path(callerDigest),
    resolved_path: path('7'.repeat(64)),
    generated_path: path(generatedDigest),
  }
}

function manifestWithRunResult(result: RunResult): Record<string, any> {
  const canonical = structuredClone(result)
  const identity = result.schema_version === '1.1'
    ? structuredClone(result.run_identity)
    : null
  const overallStatus = result.runtime_status === 'failed'
    ? 'Failed'
    : result.runtime_status === 'interrupted'
      ? 'Interrupted'
      : result.mode === 'collection' && result.collector_counts.failed_collectors > 0
        ? 'Failed'
        : {
            success: 'Passed',
            partial: 'Partial',
            failed: 'Failed',
            interrupted: 'Interrupted',
            incomplete: 'Incomplete',
          }[result.collection_status]
  return {
    ...SAMPLE_MANIFEST,
    ...(identity ? {
      run_identity: identity,
      tool_version: identity.tool.version,
      tool_config: {
        ...SAMPLE_MANIFEST.tool_config,
        collection_level: identity.invocation.resolved_level,
        collection_profile: identity.invocation.resolved_profile,
      },
    } : {}),
    run_result: canonical,
    collection_summary: {
      ...SAMPLE_MANIFEST.collection_summary,
      ...(identity ? { run_identity: structuredClone(identity) } : {}),
      overall_status: overallStatus,
      run_result: structuredClone(result),
      runtime_status: result.runtime_status,
      collection_status: result.collection_status,
      collector_counts: structuredClone(result.collector_counts),
    },
  }
}

function manifestWithSelectionFailure(failureType = 'explicit_selection_preflight_failure'): Record<string, any> {
  const result: RunResult = {
    ...structuredClone(SUCCESS_RUN_RESULT),
    collection_status: 'partial',
    collector_counts: {
      ...SUCCESS_RUN_RESULT.collector_counts,
      total_collectors: 3,
      partial_collectors: 1,
      skipped_collectors: 1,
    },
    explicit_domain_failure: true,
    affected_duts: ['DUT_1'],
    reasons: ['A collector returned partial data', 'Selected prerequisites are unavailable'],
  }
  const manifest = manifestWithRunResult(result)
  Object.assign(manifest.collection_summary, {
    overall_status: 'Failed',
    run_outcome_status: 'domain_failed',
    domain_failure: true,
    domain_failure_type: failureType,
    domain_failure_reason: result.reasons[1],
    domain_failure_evidence: '.metadata/selection_failure.json',
    run_outcome: {
      adapter_schema_version: '1.0',
      status: 'domain_failed',
      canonical_runtime_status: 'success',
      canonical_collection_status: 'partial',
      failure_type: failureType,
      reason: result.reasons[1],
      affected_duts: ['DUT_1'],
      evidence: '.metadata/selection_failure.json',
    },
  })
  return manifest
}

function installCompressedManifest(value: unknown): void {
  const raw = Buffer.from(JSON.stringify(value), 'utf-8')
  const compressed = gzipSync(raw)
  document.head.innerHTML = (
    '<script id="__NVDEBUG_MANIFEST_GZIP__" type="application/octet-stream" ' +
    'data-encoding="gzip+base64" ' +
    `data-uncompressed-bytes="${raw.byteLength}" ` +
    `data-compressed-bytes="${compressed.byteLength}">` +
    compressed.toString('base64') +
    '</script>'
  )
}

function boundedTimingFixture(
  dutId: string,
  generation = 'a'.repeat(32),
): { bytes: Uint8Array, reference: TimingReference } {
  const timing = {
    collector_started_at: '2026-08-07T00:00:00Z',
    collector_ended_at: '2026-08-07T00:00:01Z',
    wall_clock_duration_seconds: 1,
    wall_clock_is_authoritative: true as const,
    cumulative_operation_time_seconds: 0,
    operation_aggregation: 'top_level_contributing_spans' as const,
    nested_operation_time_excluded_seconds: 0,
    active_operation_union_seconds: 0,
    overlapped_operation_time_seconds: 0,
    unattributed_wall_time_seconds: 1,
    operation_sum_equals_wall_clock: false as const,
    operations: [],
    artifact_timings: [],
  }
  const document = {
    snapshot_generation: generation,
    collectors: {
      R1: { timing },
    },
  }
  const bytes = new TextEncoder().encode(JSON.stringify(document))
  return {
    bytes,
    reference: {
      schema_version: '2.0',
      scope: 'dut',
      source: `${dutId}/.metadata/timing.json`,
      collector_id: 'R1',
      size_bytes: bytes.byteLength,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      snapshot_generation: generation,
    },
  }
}

describe('manifest store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('starts with null manifest', () => {
    const store = useManifestStore()
    expect(store.manifest).toBeNull()
    expect(store.loaded).toBe(false)
  })

  it('loads from JSON', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.loaded).toBe(true)
    expect(store.manifest?.version).toBe('1.0')
  })

  it.each([
    'timeout',
    'dependency-missing',
    'auth-failure',
    'transport-failure',
    'parser-failure',
    'data-quality',
    'internal-error',
  ] as const)('retains canonical collector failure category %s', failureCategory => {
    const manifest = structuredClone(SAMPLE_MANIFEST)
    manifest.duts[0].collector_groups = [{
      name: 'redfish',
      service_type: 'redfish',
      total_execution_time: 1,
      collectors: [{
        id: 'R1',
        name: 'Synthetic failure',
        status: 'error',
        execution_time: 1,
        start_time: null,
        end_time: null,
        reason: 'synthetic terminal failure',
        failure_category: failureCategory,
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
    }]
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.duts[0].collector_groups[0].collectors[0].failure_category)
      .toBe(failureCategory)
  })

  it('preserves a degraded collector and normalizes legacy lifecycle counts', () => {
    const manifest = structuredClone(SAMPLE_MANIFEST) as any
    manifest.duts[0].status_summary = {
      success: 0, error: 0, degraded: 1, partial: 0, skipped: 0, not_ran: 0,
    }
    manifest.duts[0].overall_status = 'degraded'
    manifest.duts[0].collector_groups = [{
      name: 'redfish',
      service_type: 'redfish',
      total_execution_time: 1,
      collectors: [{
        id: 'R73',
        name: 'Synthetic degraded result',
        status: 'degraded',
        execution_time: 1,
        start_time: null,
        end_time: null,
        reason: 'one metrics target timed out',
        failure_category: 'timeout',
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
    }]
    delete manifest.collection_summary.status_counts.degraded
    const store = useManifestStore()

    store.loadFromJson(manifest)

    const collector = store.duts[0].collector_groups[0].collectors[0]
    expect(collector).toMatchObject({
      status: 'degraded',
      reason: 'one metrics target timed out',
      failure_category: 'timeout',
    })
    expect(store.duts[0].status_summary.degraded).toBe(1)
    expect(store.collectionSummary?.status_counts.degraded).toBe(0)
  })

  it('bounds and preserves generic structured collector outcome details', () => {
    const manifest = structuredClone(SAMPLE_MANIFEST) as any
    manifest.duts[0].collector_groups = [{
      name: 'bmc',
      service_type: 'bmc_ssh',
      total_execution_time: 1,
      collectors: [{
        id: 'S10',
        name: 'Logs',
        status: 'partial',
        execution_time: 1,
        start_time: null,
        end_time: null,
        reason: 'usable artifact retained',
        failure_category: 'timeout',
        dependencies: [],
        collection_level: 'L1',
        files: [],
        stage_timing: {},
        outcome_details: {
          schema_version: '1.0',
          category: 'data-quality',
          condition: 'incomplete-artifact',
          messages: ['token=secret\nmember unavailable'],
          attributes: {
            complete: false,
            members: ['log/member'],
            nested: { ignored: true },
          },
        },
      }],
    }]
    const store = useManifestStore()

    store.loadFromJson(manifest)

    const collector = store.duts[0].collector_groups[0].collectors[0]
    expect(collector.failure_category).toBe('data-quality')
    expect(collector.outcome_details).toEqual({
      schema_version: '1.0',
      category: 'data-quality',
      condition: 'incomplete-artifact',
      messages: ['token=XXXX member unavailable'],
      attributes: { complete: false, members: ['log/member'] },
    })
  })

  it('bounds collector reasons and removes stale or invalid categories', () => {
    const manifest = structuredClone(SAMPLE_MANIFEST) as any
    const collector = (status: 'success' | 'error', category: string) => ({
      id: status === 'success' ? 'R1' : 'R2',
      name: 'Synthetic result',
      status,
      execution_time: 1,
      start_time: null,
      end_time: null,
      reason: `token=XXXX\n\u0000\u2028${'x'.repeat(800)}`,
      failure_category: category,
      dependencies: [],
      collection_level: 'L1',
      files: [],
      stage_timing: {
        validation: null,
        discovery: null,
        execution: 1,
        post_processing: null,
      },
    })
    manifest.duts[0].collector_groups = [{
      name: 'redfish',
      service_type: 'redfish',
      total_execution_time: 2,
      collectors: [collector('success', 'timeout'), collector('error', 'vendor-invalid')],
    }]
    const store = useManifestStore()

    store.loadFromJson(manifest)

    const [success, invalid] = store.duts[0].collector_groups[0].collectors
    expect(success.failure_category).toBeUndefined()
    expect(invalid.failure_category).toBeUndefined()
    expect(success.reason).not.toContain('\n')
    expect(success.reason).not.toContain('\u0000')
    expect(success.reason).not.toContain('\u2028')
    expect([...success.reason]).toHaveLength(512)
    expect(new TextEncoder().encode(success.reason).byteLength).toBeLessThanOrEqual(2048)
  })

  it('retains one exact canonical result across both report surfaces', () => {
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(SUCCESS_RUN_RESULT))

    expect(store.loadError).toBeNull()
    expect(store.runResult).toEqual(SUCCESS_RUN_RESULT)
    expect(store.collectionSummary?.run_result).toEqual(SUCCESS_RUN_RESULT)
    expect(store.collectionSummary?.overall_status).toBe('Passed')
  })

  it('accepts and validates the canonical derived process exit code', () => {
    const result: RunResult = {
      ...structuredClone(IDENTITY_RUN_RESULT),
      exit_code: 0,
    }
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(result))

    expect(store.loadError).toBeNull()
    expect(store.runResult?.exit_code).toBe(0)

    const contradictory = manifestWithRunResult(result)
    contradictory.run_result.exit_code = 3
    contradictory.collection_summary.run_result.exit_code = 3
    store.loadFromJson(contradictory)
    expect(store.loadError).toContain('exit code contradicts canonical result state')
  })

  it('accepts failed overall severity for a partially successful mixed run', () => {
    const result: RunResult = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      collection_status: 'partial',
      collector_counts: {
        ...SUCCESS_RUN_RESULT.collector_counts,
        total_collectors: 2,
        failed_collectors: 1,
      },
      explicit_domain_failure: true,
      affected_duts: ['DUT_1'],
      reasons: ['One collector failed'],
    }
    const store = useManifestStore()

    store.loadFromJson(manifestWithRunResult(result))

    expect(store.loadError).toBeNull()
    expect(store.loaded).toBe(true)
    expect(store.collectionSummary?.overall_status).toBe('Failed')
  })

  it.each([
    'explicit_selection_preflight_failure',
    'explicit_selection_no_execution',
  ])('loads bounded %s evidence without changing canonical partial truth', failureType => {
    const manifest = manifestWithSelectionFailure(failureType)
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.loaded).toBe(true)
    expect(store.runResult).toEqual(manifest.run_result)
    expect(store.collectionSummary?.overall_status).toBe('Failed')
    expect(store.collectionSummary?.collection_status).toBe('partial')
    expect(store.collectionSummary?.domain_failure_type).toBe(failureType)
  })

  it('accepts a selection failure affecting a bounded subset of canonical affected DUTs', () => {
    const manifest = manifestWithSelectionFailure()
    for (const result of [manifest.run_result, manifest.collection_summary.run_result]) {
      result.dut_roster = ['DUT_1', 'DUT_2']
      result.affected_duts = ['DUT_1', 'DUT_2']
    }
    manifest.duts = [...manifest.duts, { ...structuredClone(manifest.duts[0]), id: 'DUT_2' }]
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.runResult?.affected_duts).toEqual(['DUT_1', 'DUT_2'])
    expect(store.collectionSummary?.overall_status).toBe('Failed')
  })

  it.each([
    'explicit_selection_preflight_failure',
    'explicit_selection_no_execution',
  ])('preserves interrupted severity with retained %s evidence', failureType => {
    const manifest = manifestWithSelectionFailure(failureType)
    for (const result of [manifest.run_result, manifest.collection_summary.run_result]) {
      result.runtime_status = 'interrupted'
      result.collection_status = 'interrupted'
      result.reasons[0] = 'Collection interrupted'
    }
    Object.assign(manifest.collection_summary, {
      overall_status: 'Interrupted',
      runtime_status: 'interrupted',
      collection_status: 'interrupted',
    })
    Object.assign(manifest.collection_summary.run_outcome, {
      canonical_runtime_status: 'interrupted',
      canonical_collection_status: 'interrupted',
    })
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.loaded).toBe(true)
    expect(store.runResult).toEqual(manifest.run_result)
    expect(store.collectionSummary?.overall_status).toBe('Interrupted')
    expect(store.collectionSummary?.domain_failure_type).toBe(failureType)
  })

  it('loads explicit selection failure when no requested collector could execute', () => {
    const manifest = manifestWithSelectionFailure('explicit_selection_no_execution')
    for (const result of [manifest.run_result, manifest.collection_summary.run_result]) {
      result.collection_status = 'failed'
      result.collector_counts = {
        ...result.collector_counts,
        total_collectors: 2,
        completed_collectors: 0,
        partial_collectors: 0,
        skipped_collectors: 2,
      }
    }
    manifest.collection_summary.collection_status = 'failed'
    manifest.collection_summary.collector_counts = structuredClone(manifest.run_result.collector_counts)
    manifest.collection_summary.run_outcome.canonical_collection_status = 'failed'
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.runResult?.collection_status).toBe('failed')
    expect(store.collectionSummary?.overall_status).toBe('Failed')
  })

  it.each([
    ['failure_type', 'unreviewed_failure'],
    ['evidence', '../selection_failure.json'],
    ['reason', 'A reason absent from canonical evidence'],
    ['reason', ''],
    ['affected_duts', []],
    ['affected_duts', ['DUT_1', 'DUT_1']],
    ['affected_duts', ['unrelated-dut']],
    ['affected_duts', [1]],
  ])('rejects unsupported selection evidence in %s', (field, value) => {
    const manifest = manifestWithSelectionFailure()
    manifest.collection_summary.run_outcome[field] = value
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('canonical')
  })

  it('does not accept a selection hint without canonical explicit-domain failure', () => {
    const manifest = manifestWithSelectionFailure()
    manifest.run_result.explicit_domain_failure = false
    manifest.collection_summary.run_result.explicit_domain_failure = false
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('overall_status contradicts canonical truth')
  })

  it('rejects accessor-backed selection DUT entries without evaluating them', () => {
    const manifest = manifestWithSelectionFailure()
    const getter = vi.fn(() => 'DUT_1')
    Object.defineProperty(manifest.collection_summary.run_outcome.affected_duts, '0', {
      enumerable: true,
      get: getter,
    })
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(getter).not.toHaveBeenCalled()
  })

  it('rejects duplicate selection DUTs even when their count fits the canonical roster', () => {
    const manifest = manifestWithSelectionFailure()
    for (const result of [manifest.run_result, manifest.collection_summary.run_result]) {
      result.dut_roster = ['DUT_1', 'DUT_2']
      result.affected_duts = ['DUT_1', 'DUT_2']
    }
    manifest.collection_summary.run_outcome.affected_duts = ['DUT_1', 'DUT_1']
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('overall_status contradicts canonical truth')
  })

  it.each([
    ['domain_failure_type', 'collector_result_failure'],
    ['domain_failure_reason', 'Different summary reason'],
    ['domain_failure_evidence', '.metadata/unrelated.json'],
    ['overall_status', 'Passed'],
  ])('rejects a contradictory selection projection in %s', (field, value) => {
    const manifest = manifestWithSelectionFailure()
    manifest.collection_summary[field] = value
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('canonical')
  })

  it.each([
    ['domain_failure_type', 'explicit_selection_preflight_failure'],
    ['domain_failure_reason', 'Forged selection failure'],
    ['domain_failure_evidence', '.metadata/selection_failure.json'],
  ])('rejects an orphaned %s without validated selection evidence', (field, value) => {
    const manifest = manifestWithSelectionFailure()
    delete manifest.collection_summary.run_outcome
    delete manifest.collection_summary.domain_failure_type
    delete manifest.collection_summary.domain_failure_reason
    delete manifest.collection_summary.domain_failure_evidence
    manifest.collection_summary.overall_status = 'Partial'
    manifest.collection_summary[field] = value
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('canonical truth')
  })

  it.each([
    ['domain_failure_type', 'collector_result_failure'],
    ['domain_failure_reason', 'Forged collector failure'],
    ['domain_failure_evidence', '.metadata/selection_failure.json'],
  ])('rejects %s attached to canonical success', (field, value) => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    manifest.collection_summary[field] = value
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('canonical truth')
  })

  it.each([false, true])('accepts canonical collector-failure details with nested outcome=%s', includeOutcome => {
    const manifest = manifestWithSelectionFailure()
    const reason = manifest.run_result.reasons[0]
    Object.assign(manifest.collection_summary, {
      overall_status: 'Partial',
      domain_failure_type: 'collector_result_failure',
      domain_failure_reason: reason,
    })
    delete manifest.collection_summary.domain_failure_evidence
    if (includeOutcome) {
      Object.assign(manifest.collection_summary.run_outcome, {
        failure_type: 'collector_result_failure',
        reason,
      })
      delete manifest.collection_summary.run_outcome.evidence
    } else {
      delete manifest.collection_summary.run_outcome
    }
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.loaded).toBe(true)
    expect(store.collectionSummary?.overall_status).toBe('Partial')
    expect(store.collectionSummary?.domain_failure_type).toBe('collector_result_failure')
    expect(store.collectionSummary?.domain_failure_reason).toBe(reason)
  })

  describe.each([
    'success', 'collector_result_failure', 'runtime_failed', 'interrupted',
  ] as const)('non-selection outcome evidence for %s', outcomeKind => {
    let manifest: Record<string, any>

    beforeEach(() => {
      const result = structuredClone(SUCCESS_RUN_RESULT)
      if (outcomeKind === 'collector_result_failure') {
        result.collection_status = 'partial'
        result.collector_counts.total_collectors = 2
        result.collector_counts.partial_collectors = 1
        result.explicit_domain_failure = true
      } else if (outcomeKind === 'runtime_failed') {
        result.runtime_status = 'failed'
      } else if (outcomeKind === 'interrupted') {
        result.runtime_status = 'interrupted'
        result.collection_status = 'interrupted'
      }
      if (outcomeKind !== 'success') {
        result.reasons = ['Canonical collection or runtime failure']
        result.affected_duts = ['DUT_1']
      }
      manifest = manifestWithRunResult(result)
      manifest.collection_summary.run_outcome = {
        adapter_schema_version: '1.0',
        status: outcomeKind === 'collector_result_failure' ? 'domain_failed' : outcomeKind,
        canonical_runtime_status: result.runtime_status,
        canonical_collection_status: result.collection_status,
        reason: result.reasons[0] ?? '',
        affected_duts: [...result.affected_duts],
        ...(outcomeKind === 'collector_result_failure'
          ? { failure_type: 'collector_result_failure' }
          : outcomeKind === 'runtime_failed'
            ? { failure_type: 'finalization_failure' }
            : {}),
      }
    })

    it('accepts the canonical outcome when evidence is absent', () => {
      const store = useManifestStore()

      store.loadFromJson(manifest)

      expect(store.loadError).toBeNull()
      expect(store.loaded).toBe(true)
      expect(store.collectionSummary?.run_outcome).toEqual(manifest.collection_summary.run_outcome)
      expect(store.collectionSummary?.run_outcome).not.toHaveProperty('evidence')
    })

    it.each([
      '.metadata/selection_failure.json', '.metadata/unrelated.json', '', null,
      undefined, [], { path: '.metadata/selection_failure.json' },
    ])('rejects orphaned evidence value %j', evidence => {
      manifest.collection_summary.run_outcome.evidence = evidence
      const store = useManifestStore()

      store.loadFromJson(manifest)

      expect(store.loaded).toBe(false)
      expect(store.loadError).toContain('legacy run_outcome contradicts canonical truth')
      expect(store.collectionSummary).toBeNull()
    })

    it('rejects an evidence getter without evaluating it', () => {
      const getter = vi.fn(() => '.metadata/selection_failure.json')
      Object.defineProperty(manifest.collection_summary.run_outcome, 'evidence', {
        enumerable: true,
        get: getter,
      })
      const store = useManifestStore()

      store.loadFromJson(manifest)

      expect(store.loaded).toBe(false)
      expect(store.loadError).toContain('legacy run_outcome contradicts canonical truth')
      expect(getter).not.toHaveBeenCalled()
    })
  })

  it('validates identity digests and derives every report identity projection', () => {
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(IDENTITY_RUN_RESULT))

    expect(store.loadError).toBeNull()
    expect(store.runResult).toEqual(IDENTITY_RUN_RESULT)
    expect(store.manifest?.run_identity).toEqual(RUN_IDENTITY)
    expect(store.collectionSummary?.run_identity).toEqual(RUN_IDENTITY)
    expect(store.toolVersion).toBe('2.2.0')
    expect(store.manifest?.tool_config.collection_level).toBe('L2')
    expect(store.manifest?.tool_config.collection_profile).toBe('level')
  })

  it('rejects a collection result carrying a planning identity profile', () => {
    const planningIdentity = sealIdentityFixture({
      ...structuredClone(RUN_IDENTITY),
      invocation: {
        ...structuredClone(RUN_IDENTITY.invocation),
        resolved_profile: 'planning',
      },
    })
    const result: RunResult = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      schema_version: '1.1',
      run_identity: planningIdentity,
    }
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(result))

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('mode and run_identity profile disagree')
  })

  it.each([
    [
      'configured output without a caller',
      outputFixture('configured_generated', 'absent', null, '7'.repeat(64)),
    ],
    [
      'generated descendant of a caller path',
      outputFixture('caller_based_generated', 'descendant', '8'.repeat(64), '7'.repeat(64)),
    ],
    [
      'append at the caller path',
      outputFixture('caller_supplied_append', 'same', '7'.repeat(64), null),
    ],
    [
      'append below the caller path',
      outputFixture('caller_supplied_append', 'descendant', '8'.repeat(64), null),
    ],
  ])('accepts digest-bound caller relation: %s', (_label, output) => {
    const identity = identityWithOutput(output)
    const result: RunResult = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      schema_version: '1.1',
      run_identity: identity,
    }
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(result))

    expect(store.loadError).toBeNull()
    expect(store.runIdentity?.output).toEqual(output)
  })

  it.each([
    ['identity digest', (manifest: any) => { manifest.run_result.run_identity.identity_sha256 = '0'.repeat(64) }],
    ['invocation digest', (manifest: any) => { manifest.run_result.run_identity.invocation.invocation_sha256 = '0'.repeat(64) }],
    ['extra identity field', (manifest: any) => { manifest.run_result.run_identity.untrusted = true }],
    ['legacy identity schema', (manifest: any) => { manifest.run_result.run_identity.schema_version = '1.0' }],
    ['missing catalog binding', (manifest: any) => { delete manifest.run_result.run_identity.catalog.binding }],
    ['invalid catalog binding', (manifest: any) => { manifest.run_result.run_identity.catalog.binding = 'ambient_search' }],
    ['output mode relation', (manifest: any) => { manifest.run_result.run_identity.output.generated_path.path_sha256 = null }],
    ['caller relation', (manifest: any) => { manifest.run_result.run_identity.output.caller_relation = 'same' }],
  ])('rejects malformed identity-bearing result: %s', (_label, mutate) => {
    const manifest = manifestWithRunResult(IDENTITY_RUN_RESULT)
    mutate(manifest)
    manifest.collection_summary.run_result = structuredClone(manifest.run_result)
    manifest.run_identity = structuredClone(manifest.run_result.run_identity)
    manifest.collection_summary.run_identity = structuredClone(
      manifest.run_result.run_identity,
    )
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('run_identity')
  })

  it.each([
    ['top-level identity', (manifest: any) => { manifest.run_identity.identity_sha256 = '0'.repeat(64) }],
    ['summary identity', (manifest: any) => { manifest.collection_summary.run_identity.identity_sha256 = '0'.repeat(64) }],
    ['tool version', (manifest: any) => { manifest.tool_version = '9.9.9' }],
    ['collection level', (manifest: any) => { manifest.tool_config.collection_level = 'L3' }],
    ['collection profile', (manifest: any) => { manifest.tool_config.collection_profile = 'custom' }],
  ])('rejects contradictory identity projection: %s', (_label, mutate) => {
    const manifest = manifestWithRunResult(IDENTITY_RUN_RESULT)
    mutate(manifest)
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('canonical run_result')
  })

  it('preserves a legacy result without manufacturing identity projections', () => {
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(SUCCESS_RUN_RESULT))

    expect(store.loadError).toBeNull()
    expect(store.manifest?.run_identity).toBeUndefined()
    expect(store.collectionSummary?.run_identity).toBeUndefined()
    expect(store.toolVersion).toBe(SAMPLE_MANIFEST.tool_version)
  })

  it('normalizes historical run-result copies without degraded_collectors to zero', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT) as any
    delete manifest.run_result.collector_counts.degraded_collectors
    delete manifest.collection_summary.run_result.collector_counts.degraded_collectors
    delete manifest.collection_summary.collector_counts.degraded_collectors
    const store = useManifestStore()

    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.runResult?.collector_counts).toMatchObject({
      completed_collectors: 1,
      degraded_collectors: 0,
    })
    expect(store.collectionSummary?.collector_counts).toMatchObject({
      degraded_collectors: 0,
    })
  })

  it('rejects divergent top-level and summary canonical results', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    manifest.collection_summary.run_result = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      collection_status: 'failed',
      collector_counts: {
        ...SUCCESS_RUN_RESULT.collector_counts,
        completed_collectors: 0,
        failed_collectors: 1,
      },
      affected_duts: ['DUT_1'],
      reasons: ['Collector failed'],
    }
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('top-level and collection_summary copies differ')
  })

  it.each([
    ['unexpected field', (result: any) => { result.untrusted = true }],
    ['inconsistent total', (result: any) => { result.collector_counts.total_collectors = 2 }],
    ['oversized count', (result: any) => { result.collector_counts.completed_collectors = 100_001 }],
    ['missing roster', (result: any) => { result.dut_roster = [] }],
    ['multibyte roster beyond byte limit', (result: any) => { result.dut_roster = ['é'.repeat(255)] }],
    ['NBSP roster separator', (result: any) => { result.dut_roster = ['DUT\u00a01'] }],
    ['EM SPACE roster separator', (result: any) => { result.dut_roster = ['DUT\u20031'] }],
    ['private-use roster code point', (result: any) => { result.dut_roster = ['DUT\ue0001'] }],
    ['unassigned roster code point', (result: any) => { result.dut_roster = ['DUT\u03781'] }],
    ['private-use reason code point', (result: any) => { result.reasons = ['failed\ue000now'] }],
    ['unassigned reason code point', (result: any) => { result.reasons = ['failed\u0378now'] }],
    ['line-separator reason', (result: any) => { result.reasons = ['failed\u2028now'] }],
    ['foreign affected DUT', (result: any) => { result.affected_duts = ['DUT_2'] }],
    ['contradictory status', (result: any) => { result.collection_status = 'partial' }],
  ])('rejects a hostile canonical result with %s', (_label, mutate) => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    mutate(manifest.run_result)
    manifest.collection_summary.run_result = structuredClone(manifest.run_result)
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('Invalid canonical run_result')
  })

  it('accepts a printable multibyte identity within the UTF-8 byte bound', () => {
    const identity = 'é'.repeat(127)
    const result = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      dut_roster: [identity],
    }
    const store = useManifestStore()
    store.loadFromJson(manifestWithRunResult(result))

    expect(store.loadError).toBeNull()
    expect(store.runResult?.dut_roster).toEqual([identity])
  })

  it('rejects accessor-backed canonical fields', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    const hostile = structuredClone(SUCCESS_RUN_RESULT) as Record<string, any>
    Object.defineProperty(hostile, 'runtime_status', {
      enumerable: true,
      get: () => 'success',
    })
    manifest.run_result = hostile
    manifest.collection_summary.run_result = hostile
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('document fields are not exact')
  })

  it('does not honor toJSON while comparing an untrusted summary projection', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    manifest.collection_summary.runtime_status = {
      toJSON: () => SUCCESS_RUN_RESULT.runtime_status,
    }
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('runtime_status contradicts canonical truth')
  })

  it('rejects accessor-backed summary collector counts', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    const counts = structuredClone(SUCCESS_RUN_RESULT.collector_counts)
    Object.defineProperty(counts, 'completed_collectors', {
      enumerable: true,
      get: () => 1,
    })
    manifest.collection_summary.collector_counts = counts
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('collector_counts contradicts canonical truth')
  })

  it('rejects accessor-backed legacy affected DUTs', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    const legacy: Record<string, any> = { status: 'success' }
    Object.defineProperty(legacy, 'affected_duts', {
      enumerable: true,
      get: () => [],
    })
    manifest.collection_summary.run_outcome = legacy
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('legacy run_outcome contradicts canonical truth')
  })

  it('enforces the canonical 512-character reason bound', () => {
    const oversized = manifestWithRunResult({
      ...structuredClone(SUCCESS_RUN_RESULT),
      runtime_status: 'failed',
      collection_status: 'success',
      reasons: ['x'.repeat(513)],
    })
    const rejectedStore = useManifestStore()
    rejectedStore.loadFromJson(oversized)
    expect(rejectedStore.loaded).toBe(false)
    expect(rejectedStore.loadError).toContain('snapshot flags or reasons are invalid')

    setActivePinia(createPinia())
    const boundary = manifestWithRunResult({
      ...structuredClone(SUCCESS_RUN_RESULT),
      runtime_status: 'failed',
      collection_status: 'success',
      reasons: ['🛠'.repeat(512)],
    })
    const acceptedStore = useManifestStore()
    acceptedStore.loadFromJson(boundary)
    expect(acceptedStore.loadError).toBeNull()
    expect(acceptedStore.runResult?.reasons[0]).toBe('🛠'.repeat(512))
  })

  it('rejects success-only wording as a non-success reason', () => {
    const manifest = manifestWithRunResult({
      ...structuredClone(SUCCESS_RUN_RESULT),
      runtime_status: 'failed',
      reasons: ['Completed successfully'],
    })
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('missing a failure reason')
  })

  it('rejects contradictory summary projections', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    manifest.collection_summary.runtime_status = 'failed'
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('runtime_status contradicts canonical truth')
  })

  it.each([
    ['run_outcome_failure_type', 'finalization_failure'],
    ['run_outcome_reason', 'contradictory reason'],
    ['domain_failure', true],
    ['underlying_outcome', { status: 'domain_failed' }],
  ])('rejects contradictory legacy summary field %s', (field, value) => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    manifest.collection_summary[field] = value
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('legacy')
  })

  it('rejects a nested legacy failure type when canonical success has none', () => {
    const manifest = manifestWithRunResult(SUCCESS_RUN_RESULT)
    manifest.collection_summary.run_outcome = {
      status: 'success',
      failure_type: 'finalization_failure',
      reason: '',
      affected_duts: [],
    }
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('legacy run_outcome contradicts canonical truth')
  })

  it('never projects an incomplete canonical collection as legacy success', () => {
    const incomplete: RunResult = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      collection_status: 'incomplete',
      collector_counts: {
        ...SUCCESS_RUN_RESULT.collector_counts,
        pending_collectors: 1,
        completed_collectors: 0,
      },
      reasons: ['Collection did not reach a complete terminal outcome'],
    }
    const manifest = manifestWithRunResult(incomplete)
    manifest.collection_summary.run_outcome_status = 'runtime_failed'
    manifest.collection_summary.run_outcome = {
      adapter_schema_version: '1.0',
      status: 'runtime_failed',
      canonical_runtime_status: 'success',
      canonical_collection_status: 'incomplete',
      failure_type: 'incomplete_collection',
      reason: incomplete.reasons[0],
      affected_duts: [],
    }
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.runResult?.collection_status).toBe('incomplete')
    expect(store.collectionSummary?.overall_status).toBe('Incomplete')
    expect(store.collectionSummary?.run_outcome_status).toBe('runtime_failed')

    const contradictory = structuredClone(manifest)
    contradictory.collection_summary.run_outcome_status = 'success'
    contradictory.collection_summary.run_outcome.status = 'success'
    setActivePinia(createPinia())
    const rejectedStore = useManifestStore()
    rejectedStore.loadFromJson(contradictory)
    expect(rejectedStore.loaded).toBe(false)
    expect(rejectedStore.loadError).toContain('legacy outcome status contradicts')
  })

  it('accepts an all-skipped plan only as an incomplete collection', () => {
    const incomplete: RunResult = {
      ...structuredClone(SUCCESS_RUN_RESULT),
      collection_status: 'incomplete',
      collector_counts: {
        ...SUCCESS_RUN_RESULT.collector_counts,
        completed_collectors: 0,
        skipped_collectors: 1,
      },
      reasons: ['Collection scheduled work but produced no evidence'],
    }
    const manifest = manifestWithRunResult(incomplete)
    manifest.collection_summary.run_outcome_status = 'runtime_failed'
    manifest.collection_summary.run_outcome = {
      adapter_schema_version: '1.0',
      status: 'runtime_failed',
      canonical_runtime_status: 'success',
      canonical_collection_status: 'incomplete',
      failure_type: 'incomplete_collection',
      reason: incomplete.reasons[0],
      affected_duts: [],
    }
    const store = useManifestStore()
    store.loadFromJson(manifest)

    expect(store.loadError).toBeNull()
    expect(store.runResult?.collection_status).toBe('incomplete')

    const contradictory = structuredClone(manifest)
    contradictory.run_result.collection_status = 'success'
    contradictory.run_result.reasons = []
    contradictory.collection_summary.run_result = structuredClone(contradictory.run_result)
    setActivePinia(createPinia())
    const rejectedStore = useManifestStore()
    rejectedStore.loadFromJson(contradictory)
    expect(rejectedStore.loaded).toBe(false)
    expect(rejectedStore.loadError).toContain('statuses contradict canonical collector counts')
  })

  it('drops malformed file-index entries at the manifest boundary', () => {
    const store = useManifestStore()
    const valid = SAMPLE_MANIFEST.file_index[0]
    store.loadFromJson({
      ...SAMPLE_MANIFEST,
      file_index: [null, undefined, 7, true, [], {}, { path: 42 }, valid],
    })

    expect(store.fileIndex).toEqual([valid])
  })

  it('normalizes bounded plain-data errors at the manifest boundary', () => {
    const getterEntry = {
      ...SAMPLE_MANIFEST.errors[0],
      get message() {
        throw new Error('must not invoke attacker getter')
      },
    }
    const proxyEntry = new Proxy(SAMPLE_MANIFEST.errors[0], {
      getOwnPropertyDescriptor() {
        throw new Error('must contain attacker proxy failure')
      },
    })
    const longText = 'x'.repeat(240)
    const valid = {
      dut_id: `dut-${longText}`,
      collector_id: `collector-${longText}`,
      collector_name: `name-${longText}`,
      collector_group: `group-${longText}`,
      message: `message-${longText}`,
      timestamp: `timestamp-${longText}`,
    }
    const store = useManifestStore()
    store.loadFromJson({
      ...SAMPLE_MANIFEST,
      errors: [null, undefined, 7, true, 'error', [], {}, getterEntry, proxyEntry, valid],
    })

    expect(store.loadError).toBeNull()
    expect(store.errors).toEqual([{
      dut_id: valid.dut_id.slice(0, 200),
      collector_id: valid.collector_id.slice(0, 200),
      collector_name: valid.collector_name.slice(0, 200),
      collector_group: valid.collector_group.slice(0, 200),
      message: valid.message,
      timestamp: valid.timestamp.slice(0, 200),
    }])
  })

  it('bounds manifest error normalization against hostile sparse lengths', () => {
    let indexReads = 0
    const sparseErrors = new Proxy([], {
      get(target, property, receiver) {
        if (property === 'length') return Number.MAX_SAFE_INTEGER
        if (typeof property === 'string' && /^\d+$/u.test(property)) indexReads++
        return Reflect.get(target, property, receiver)
      },
    })
    const store = useManifestStore()

    store.loadFromJson({ ...SAMPLE_MANIFEST, errors: sparseErrors })

    expect(store.loadError).toBeNull()
    expect(store.errors).toEqual([])
    expect(indexReads).toBe(ERROR_CLUSTER_INPUT_LIMIT)
  })

  it('returns duts', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.duts).toHaveLength(1)
    expect(store.duts[0].id).toBe('DUT_1')
  })

  it('finds DUT by id', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.dutById('DUT_1')?.baseboard).toBe('HGX_H100')
    expect(store.dutById('NONEXISTENT')).toBeUndefined()
  })

  it('filters files by DUT', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.filesByDut('DUT_1')).toHaveLength(2)
    expect(store.filesByDut('DUT_2')).toHaveLength(0)
  })

  it('returns global status counts', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.globalStatusCounts.success).toBe(10)
    expect(store.globalStatusCounts.error).toBe(2)
  })

  it('returns errors', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.errors).toHaveLength(1)
    expect(store.errors[0].message).toBe('Connection timeout')
  })

  it('scrubs and bounds error messages at the manifest boundary', () => {
    const manifest = structuredClone(SAMPLE_MANIFEST)
    manifest.errors[0].message = `token=super-secret\n\u0000${'x'.repeat(800)}`
    const store = useManifestStore()

    store.loadFromJson(manifest)

    const message = store.errors[0].message
    expect(message).toContain('token=XXXX')
    expect(message).not.toContain('super-secret')
    expect(message).not.toContain('\n')
    expect(message).not.toContain('\u0000')
    expect([...message]).toHaveLength(512)
    expect(new TextEncoder().encode(message).byteLength).toBeLessThanOrEqual(2048)
  })

  it('provides a safe empty core dump handoff for older manifests', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)

    expect(store.openBMCCoreDumps?.core_dumps).toEqual([])
    expect(store.openBMCCoreDumps?.summary).toEqual({
      core_dump_count: 0,
      analyzer_ready_count: 0,
      needs_metadata_count: 0,
    })
    expect(store.openBMCCoreDumps?.analyzer.automatic_upload).toBe(false)
    expect(store.openBMCCoreDumps?.archive_scan).toEqual({
      complete: true,
      archives_inspected: 0,
      compressed_bytes_inspected: 0,
      decompressed_bytes_consumed: 0,
      members_inspected: 0,
      uninspected_archive_count: 0,
      uninspected_archive_details_omitted: 0,
      uninspected_archives: [],
    })
  })

  it('uses only the report build configuration for the analyzer link', () => {
    vi.stubEnv(
      'VITE_OPENBMC_COREDUMP_ANALYZER_URL',
      'https://approved.example/analyzer',
    )
    try {
      const store = useManifestStore()
      store.loadFromJson({
        ...SAMPLE_MANIFEST,
        openbmc_coredumps: {
          analyzer: { url: 'https://untrusted.invalid/upload' },
          core_dumps: [],
        },
      })

      expect(store.openBMCCoreDumps?.analyzer.url).toBe(
        'https://approved.example/analyzer',
      )
    } finally {
      vi.unstubAllEnvs()
    }
  })

  it('normalizes core dump handoff data and never enables automatic upload', () => {
    const store = useManifestStore()
    store.loadFromJson({
      ...SAMPLE_MANIFEST,
      openbmc_coredumps: {
        analyzer: {
          url: 'https://example.invalid/fake-analyzer',
          automatic_upload: true,
        },
        summary: {
          core_dump_count: 99,
          analyzer_ready_count: 99,
          needs_metadata_count: 0,
        },
        scan_warnings: ['One archive was bounded.'],
        archive_scan: {
          complete: true,
          archives_inspected: 2,
          compressed_bytes_inspected: 2048,
          decompressed_bytes_consumed: 8192,
          members_inspected: 17,
          uninspected_archive_count: 3,
          uninspected_archive_details_omitted: 2,
          uninspected_archives: [
            {
              artifact_path: 'DUT_1/redfish/dump.tar.xz',
              size_bytes: 512,
              status: 'partial',
              reason: 'archive_member_limit',
            },
          ],
        },
        core_dumps: [
          {
            path: 'DUT_1/bmc/core.example.42.xz',
            archive_member_path: 'dump/core.example.42.xz',
            outer_archive_size_bytes: 1024,
            size: -10,
            dut_id: 'DUT_1',
            collector_id: 'S10',
            commit: 'deadbeef',
            machine: 'test-machine',
            service: 'example',
            ready_for_analyzer: true,
            preparation_required: ['Decompress the core while preserving the original.'],
            handoff: {
              action: 'automatic_upload',
              analyzer_url: 'https://example.invalid/collect-core',
              upload_performed: true,
            },
          },
          'not-a-record',
        ],
      },
    })

    const handoff = store.openBMCCoreDumps!
    expect(handoff.analyzer.url).toBeNull()
    expect(handoff.analyzer.automatic_upload).toBe(false)
    expect(handoff.summary).toEqual({
      core_dump_count: 1,
      analyzer_ready_count: 0,
      needs_metadata_count: 1,
    })

    const core = handoff.core_dumps[0]
    expect(core.artifact_path).toBe('DUT_1/bmc/core.example.42.xz')
    expect(core.archive_member_path).toBe('dump/core.example.42.xz')
    expect(core.outer_archive_size_bytes).toBe(1024)
    expect(core.filename).toBe('core.example.42.xz')
    expect(core.size_bytes).toBe(0)
    expect(core.openbmc_commit).toBe('deadbeef')
    expect(core.collector.id).toBe('S10')
    expect(core.ready_for_analyzer).toBe(false)
    expect(core.preparation_required).toEqual([
      'Decompress the core while preserving the original.',
    ])
    expect(core.handoff).toEqual({
      action: 'manual_upload',
      analyzer_url: null,
      upload_performed: false,
    })
    expect(handoff.scan_warnings).toEqual(['One archive was bounded.'])
    expect(handoff.archive_scan.complete).toBe(false)
    expect(handoff.archive_scan.members_inspected).toBe(17)
    expect(handoff.archive_scan.uninspected_archive_count).toBe(3)
    expect(handoff.archive_scan.uninspected_archive_details_omitted).toBe(2)
    expect(handoff.archive_scan.uninspected_archives).toEqual([
      {
        artifact_path: 'DUT_1/redfish/dump.tar.xz',
        size_bytes: 512,
        status: 'partial',
        reason: 'archive_member_limit',
      },
    ])
  })

  it('derives readiness counts from normalized core records', () => {
    const store = useManifestStore()
    store.loadFromJson({
      ...SAMPLE_MANIFEST,
      openbmc_coredumps: {
        core_dumps: [
          {
            artifact_path: 'DUT_1/bmc/core.ready',
            source_dut: 'DUT_1',
            openbmc_commit: '1234567890abcdef', // pragma: allowlist secret
            machine: 'test-machine',
            service: null,
            validation: 'validated_raw_elf_core',
            ready_for_analyzer: true,
            missing_required_metadata: [],
            preparation_required: [],
          },
          {
            artifact_path: 'DUT_1/bmc/core.missing',
            source_dut: 'DUT_1',
            openbmc_commit: null,
            machine: null,
            ready_for_analyzer: true,
          },
        ],
      },
    })

    expect(store.openBMCCoreDumps?.summary).toEqual({
      core_dump_count: 2,
      analyzer_ready_count: 1,
      needs_metadata_count: 1,
    })
    expect(
      store.openBMCCoreDumps?.core_dumps[1].missing_required_metadata,
    ).toEqual(['openbmc_commit', 'machine', 'valid_core_dump'])
  })

  it('never trusts an unknown validation state as analyzer-ready', () => {
    const store = useManifestStore()
    store.loadFromJson({
      ...SAMPLE_MANIFEST,
      openbmc_coredumps: {
        core_dumps: [
          {
            artifact_path: 'DUT_1/bmc/core.unknown',
            source_dut: 'DUT_1',
            openbmc_commit: '1234567890abcdef', // pragma: allowlist secret
            machine: 'test-machine',
            validation: 'unknown-from-older-manifest',
            ready_for_analyzer: true,
            missing_required_metadata: [],
            preparation_required: [],
          },
        ],
      },
    })

    const core = store.openBMCCoreDumps!.core_dumps[0]
    expect(core.ready_for_analyzer).toBe(false)
    expect(core.missing_required_metadata).toContain('valid_core_dump')
  })
})

describe('bounded manifest loading', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    document.head.innerHTML = ''
    window.__MANIFEST__ = undefined
  })

  it('reports actual HTTP chunk bytes before parsing and validation', async () => {
    const bytes = new TextEncoder().encode(JSON.stringify(SAMPLE_MANIFEST))
    const chunks = [bytes.slice(0, 100), bytes.slice(100, 300), bytes.slice(300)]
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk)
        controller.close()
      },
    }), { headers: { 'content-length': String(bytes.byteLength) } })))
    vi.stubGlobal('location', { protocol: 'http:', href: 'http://localhost/reports/index.html' })
    const report = vi.fn<ReportLoadReporter>(async () => undefined)
    try {
      const store = useManifestStore()
      await store.loadInitial(report)
      expect(store.loaded).toBe(true)
      expect(report.mock.calls.map(([progress]) => progress)).toEqual([
        { stage: 'reading', bytesRead: 0 },
        ...[100, 300, bytes.byteLength].map(bytesRead => ({ stage: 'reading', bytesRead, totalBytes: bytes.byteLength })),
        { stage: 'parsing' },
        { stage: 'validating' },
      ])
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('does not use compressed HTTP Content-Length as a decoded byte total', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(SAMPLE_MANIFEST), {
      headers: { 'content-encoding': 'gzip', 'content-length': '100' },
    })))
    vi.stubGlobal('location', { protocol: 'http:', href: 'http://localhost/reports/index.html' })
    const report = vi.fn<ReportLoadReporter>(async () => undefined)
    try {
      await useManifestStore().loadInitial(report)
      expect(report).toHaveBeenCalledWith({
        stage: 'reading', bytesRead: expect.any(Number), totalBytes: null,
      })
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('reports offline decoding and decompression progress before parsing', async () => {
    const value = { text: 'é'.repeat(100_000) }
    installCompressedManifest(value)
    const report = vi.fn<ReportLoadReporter>(async () => undefined)
    expect(await decodeEmbeddedManifest(document, report)).toEqual(value)
    const rawSize = new TextEncoder().encode(JSON.stringify(value)).byteLength
    expect(report).toHaveBeenCalledWith({ stage: 'decoding', bytesRead: 0, totalBytes: expect.any(Number) })
    expect(report).toHaveBeenCalledWith({ stage: 'decompressing', bytesRead: rawSize, totalBytes: rawSize })
    expect(report).toHaveBeenLastCalledWith({ stage: 'parsing' })
    expect(report.mock.calls.filter(([progress]) => progress.stage === 'decompressing').length).toBeGreaterThan(2)
  })

  it('decodes the compressed file fallback without an external request', async () => {
    installCompressedManifest(SAMPLE_MANIFEST)
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', { protocol: 'file:', href: 'file:///tmp/reports/index.html' })
    try {
      expect(await decodeEmbeddedManifest()).toEqual(SAMPLE_MANIFEST)
      const store = useManifestStore()
      await store.loadInitial()
      expect(store.loaded).toBe(true)
      expect(store.manifest?.tool_version).toBe('2.1.0')
      expect(fetchMock).not.toHaveBeenCalled()
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('prefers bounded standalone manifest JSON over HTTP', async () => {
    installCompressedManifest({ ...SAMPLE_MANIFEST, tool_version: 'fallback' })
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(SAMPLE_MANIFEST), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', { protocol: 'http:', href: 'http://localhost/reports/index.html' })
    try {
      const store = useManifestStore()
      await store.loadInitial()
      expect(store.loaded).toBe(true)
      expect(store.manifest?.tool_version).toBe('2.1.0')
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects an oversized standalone declaration before reading its body', async () => {
    const cancel = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(new ReadableStream<Uint8Array>({ cancel }), {
        status: 200,
        headers: { 'content-length': String(129 * 1024 * 1024) },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', { protocol: 'http:', href: 'http://localhost/reports/index.html' })
    try {
      const store = useManifestStore()
      await store.loadInitial()
      expect(store.loaded).toBe(false)
      expect(store.loadError).toContain('oversized Content-Length')
      expect(cancel).toHaveBeenCalledTimes(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('loads and caches one bounded canonical timing document on demand', async () => {
    const reference = {
      schema_version: '2.0' as const,
      scope: 'dut' as const,
      source: 'DUT_1/.metadata/timing.json',
      collector_id: 'R1',
      size_bytes: 0,
      sha256: '0'.repeat(64),
      snapshot_generation: 'a'.repeat(32),
    }
    const manifest = structuredClone(SAMPLE_MANIFEST)
    manifest.duts[0].collector_groups = [{
      name: 'redfish',
      service_type: 'redfish',
      total_execution_time: 1,
      collectors: [{
        id: 'R1',
        name: 'Systems',
        status: 'success',
        execution_time: 1,
        start_time: null,
        end_time: null,
        reason: '',
        dependencies: [],
        collection_level: 'L1',
        timing_ref: reference,
        files: [{
          path: 'DUT_1/redfish/Systems.json',
          size: 2,
          type: 'json',
          collector_id: 'R1',
        }],
        stage_timing: {
          validation: null,
          discovery: null,
          execution: 1,
          post_processing: null,
        },
      }],
    }]
    const canonicalTiming = {
      snapshot_generation: 'a'.repeat(32),
      collectors: {
        R1: {
          timing: {
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
            operations: [],
            artifact_timings: [{
              path: 'DUT_1/redfish/Systems.json',
              operation_id: 'op-1',
              measurement: 'redfish_request',
              measurement_quality: 'measured',
              measurement_scope: 'artifact',
              shared_operation_artifact_count: 1,
              started_at: '2026-08-07T00:00:00Z',
              ended_at: '2026-08-07T00:00:01Z',
              duration_seconds: 1,
              size_bytes: 2,
              status: 'success',
            }],
          },
        },
      },
    }
    const timingJson = JSON.stringify(canonicalTiming)
    const timingBytes = new TextEncoder().encode(timingJson)
    const timingDigest = await crypto.subtle.digest('SHA-256', timingBytes)
    reference.size_bytes = timingBytes.byteLength
    reference.sha256 = [...new Uint8Array(timingDigest)]
      .map(value => value.toString(16).padStart(2, '0'))
      .join('')
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(timingBytes, { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(manifest)
      const timing = await store.loadCollectorTiming('DUT_1', 'R1', reference)
      await store.loadCollectorTiming('DUT_1', 'R1', reference)
      const collector = store.manifest!.duts[0].collector_groups[0].collectors[0]
      expect(timing.wall_clock_duration_seconds).toBe(1)
      expect(collector.timing).toBeUndefined()
      expect(collector.files[0].measurement).toBeUndefined()
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects timing bytes whose digest does not match the reference', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    fixture.reference.sha256 = '0'.repeat(64)
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(
      new Response(fixture.bytes, { status: 200 }),
    ))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      await expect(
        store.loadCollectorTiming('DUT_1', 'R1', fixture.reference),
      ).rejects.toThrow('digest does not match')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('verifies and loads timing without crypto.subtle (insecure-context fallback)', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(
      new Response(fixture.bytes, { status: 200 }),
    ))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://workstation.example.com/reports/index.html',
    })
    // Plain-http non-localhost pages expose `crypto` without `subtle`.
    vi.stubGlobal('crypto', {})
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      const timing = await store.loadCollectorTiming('DUT_1', 'R1', fixture.reference)
      expect(timing.wall_clock_duration_seconds).toBe(1)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('still rejects mismatched digests without crypto.subtle', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    fixture.reference.sha256 = '0'.repeat(64)
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(
      new Response(fixture.bytes, { status: 200 }),
    ))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://workstation.example.com/reports/index.html',
    })
    vi.stubGlobal('crypto', {})
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      await expect(
        store.loadCollectorTiming('DUT_1', 'R1', fixture.reference),
      ).rejects.toThrow('digest does not match')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('does not reuse cached timing across a changed snapshot binding', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(
      new Response(fixture.bytes, { status: 200 }),
    ))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      await store.loadCollectorTiming('DUT_1', 'R1', fixture.reference)
      const changedReference = {
        ...fixture.reference,
        snapshot_generation: 'b'.repeat(32),
      }
      await expect(
        store.loadCollectorTiming('DUT_1', 'R1', changedReference),
      ).rejects.toThrow('snapshot does not match')
      expect(fetchMock).toHaveBeenCalledTimes(2)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('cancels an oversized timing response before consuming its body', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    const cancel = vi.fn()
    const body = new ReadableStream<Uint8Array>({ cancel })
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: { 'content-length': String(17 * 1024 * 1024) },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      await expect(
        store.loadCollectorTiming('DUT_1', 'R1', fixture.reference),
      ).rejects.toThrow('oversized Content-Length')
      expect(cancel).toHaveBeenCalledTimes(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('deduplicates concurrent loads of one exact timing binding', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    let release: ((response: Response) => void) | undefined
    const response = new Promise<Response>(resolve => { release = resolve })
    const fetchMock = vi.fn().mockImplementation(() => response)
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      const first = store.loadCollectorTiming('DUT_1', 'R1', fixture.reference)
      const second = store.loadCollectorTiming('DUT_1', 'R1', fixture.reference)
      expect(fetchMock).toHaveBeenCalledTimes(1)
      release!(new Response(fixture.bytes, { status: 200 }))
      await expect(Promise.all([first, second])).resolves.toHaveLength(2)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects rather than queues the fifth distinct concurrent timing load', async () => {
    const fixtures = Array.from(
      { length: 5 },
      (_, index) => boundedTimingFixture(`DUT_${index}`),
    )
    const releases: Array<(response: Response) => void> = []
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>(resolve => {
      releases.push(resolve)
    }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      const active = fixtures.slice(0, 4).map((fixture, index) =>
        store.loadCollectorTiming(`DUT_${index}`, 'R1', fixture.reference),
      )
      await expect(
        store.loadCollectorTiming('DUT_4', 'R1', fixtures[4].reference),
      ).rejects.toThrow('5th distinct request is rejected')
      expect(fetchMock).toHaveBeenCalledTimes(4)
      releases.forEach((releaseResponse, index) => {
        releaseResponse(new Response(fixtures[index].bytes, { status: 200 }))
      })
      await Promise.all(active)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('does not serve or cache a prior-generation in-flight timing promise', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    let releaseOld: ((response: Response) => void) | undefined
    const oldResponse = new Promise<Response>(resolve => { releaseOld = resolve })
    const fetchMock = vi.fn()
      .mockImplementationOnce(() => oldResponse)
      .mockImplementationOnce(() => Promise.resolve(
        new Response(fixture.bytes, { status: 200 }),
      ))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      const oldLoad = store.loadCollectorTiming('DUT_1', 'R1', fixture.reference)

      store.loadFromJson(structuredClone(SAMPLE_MANIFEST))
      const current = await store.loadCollectorTiming(
        'DUT_1', 'R1', fixture.reference,
      )
      expect(current.wall_clock_duration_seconds).toBe(1)
      expect(fetchMock).toHaveBeenCalledTimes(2)

      releaseOld!(new Response(fixture.bytes, { status: 200 }))
      await oldLoad
      await store.loadCollectorTiming('DUT_1', 'R1', fixture.reference)
      expect(fetchMock).toHaveBeenCalledTimes(2)
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects malformed entries anywhere in a referenced timing document', async () => {
    const fixture = boundedTimingFixture('DUT_1')
    const document = JSON.parse(new TextDecoder().decode(fixture.bytes))
    document.collectors.R2 = {
      timing: {
        operations: [{ operation_id: 'op-with-missing-shape' }],
        artifact_timings: [],
      },
    }
    const bytes = new TextEncoder().encode(JSON.stringify(document))
    fixture.reference.size_bytes = bytes.byteLength
    fixture.reference.sha256 = createHash('sha256').update(bytes).digest('hex')
    const fetchMock = vi.fn().mockResolvedValue(new Response(bytes, { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      await expect(
        store.loadCollectorTiming('DUT_1', 'R1', fixture.reference),
      ).rejects.toThrow('operation or artifact entry is malformed')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('evicts least-recently-used timing documents at the aggregate entry cap', async () => {
    const fixtures = Array.from(
      { length: 9 },
      (_, index) => boundedTimingFixture(`DUT_${index}`),
    )
    const fetchMock = vi.fn().mockImplementation((input: URL | RequestInfo) => {
      const requested = String(input)
      const fixture = fixtures.find(entry => requested.endsWith(entry.reference.source))
      if (!fixture) throw new Error(`Unexpected timing request: ${requested}`)
      return Promise.resolve(new Response(fixture.bytes, { status: 200 }))
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('location', {
      protocol: 'http:',
      href: 'http://localhost/reports/index.html',
    })
    try {
      const store = useManifestStore()
      store.loadFromJson(SAMPLE_MANIFEST)
      for (const [index, fixture] of fixtures.entries()) {
        await store.loadCollectorTiming(`DUT_${index}`, 'R1', fixture.reference)
      }
      await store.loadCollectorTiming('DUT_0', 'R1', fixtures[0].reference)
      expect(fetchMock).toHaveBeenCalledTimes(10)
      expect(JSON.stringify(store.manifest)).not.toContain('collector_started_at')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('rejects manifests with more than 500 DUTs', () => {
    const store = useManifestStore()
    const manifest = structuredClone(SAMPLE_MANIFEST)
    manifest.duts = Array.from({ length: 501 }, (_, index) => ({
      ...structuredClone(SAMPLE_MANIFEST.duts[0]),
      id: `DUT_${index}`,
    }))

    store.loadFromJson(manifest)

    expect(store.loaded).toBe(false)
    expect(store.loadError).toContain('DUT count exceeds')
  })
})
