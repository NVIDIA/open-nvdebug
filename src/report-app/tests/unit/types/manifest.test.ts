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

import { describe, expect, expectTypeOf, it } from 'vitest'
import type {
  AccessPath,
  CollectionSummary,
  DUT,
  FileEntry,
  Manifest,
  OpenBMCCoreDumpManifest,
  PlatformIdentity,
  RunIdentity,
  RunOutcome,
  RunResult,
  SecurityModeMetadata,
} from '../../../src/types/manifest'

const underlyingOutcome: RunOutcome = {
  status: 'runtime_failed',
  reason: 'archive finalization failed',
  affected_duts: ['DUT_1'],
  failure_type: 'finalization_failure',
  evidence: '.metadata/archive_failure.json',
}

const interruptedOutcome: RunOutcome = {
  status: 'interrupted',
  reason: 'collection interrupted',
  affected_duts: ['DUT_1'],
  underlying_outcome: underlyingOutcome,
}

const summary: CollectionSummary = {
  total_duts: 1,
  total_collectors_executed: 1,
  total_collectors_in_catalog: 1,
  total_collectors_filtered_out: 0,
  total_log_size: 0,
  total_runtime: 0,
  overall_collection_pct: 0,
  overall_status: 'Interrupted',
  domain_failure: false,
  run_outcome_status: 'interrupted',
  run_outcome_reason: interruptedOutcome.reason,
  run_outcome: interruptedOutcome,
  underlying_outcome: underlyingOutcome,
  status_counts: {
    success: 0,
    error: 0,
    partial: 0,
    skipped: 0,
  },
}

const dutStatus: DUT['overall_status'] = 'interrupted'

const coreDumpHandoff: OpenBMCCoreDumpManifest = {
  schema_version: '1.0',
  generated_at: '2026-07-30T00:00:00Z',
  analyzer: {
    name: 'OpenBMC Core Dump Analyzer',
    url: null,
    integration_mode: 'manual_handoff',
    automatic_upload: false,
  },
  privacy: {
    classification: 'sensitive_diagnostic_artifact',
    notice: 'Manual review is required.',
  },
  summary: {
    core_dump_count: 1,
    analyzer_ready_count: 1,
    needs_metadata_count: 0,
  },
  scan_warnings: [],
  archive_scan: {
    complete: true,
    archives_inspected: 0,
    compressed_bytes_inspected: 0,
    decompressed_bytes_consumed: 0,
    members_inspected: 0,
    uninspected_archive_count: 0,
    uninspected_archive_details_omitted: 0,
    uninspected_archives: [],
  },
  core_dumps: [
    {
      artifact_path: 'DUT_1/bmc/core.example.42',
      archive_member_path: null,
      filename: 'core.example.42',
      size_bytes: 128,
      outer_archive_size_bytes: null,
      source_dut: 'DUT_1',
      collector: { id: 'S10', name: 'BMC logs', group: 'bmc', path: 'DUT_1/bmc' },
      openbmc_commit: 'deadbeef',
      machine: 'test-machine',
      baseboard: 'Test Baseboard',
      service: 'example',
      pid: 42,
      timestamp: '2026-07-30T00:00:00Z',
      compression: 'raw',
      validation: 'validated_raw_elf_core',
      metadata_sources: {
        openbmc_commit: 'dut_metadata',
        machine: 'catalog',
        service: 'filename',
      },
      ready_for_analyzer: true,
      missing_required_metadata: [],
      warnings: [],
      preparation_required: [],
      handoff: {
        action: 'manual_upload',
        analyzer_url: null,
        upload_performed: false,
      },
    },
  ],
}

describe('manifest terminal outcome types', () => {
  it('represent the terminal outcome fields emitted by run bundles', () => {
    expectTypeOf(summary.run_outcome).toEqualTypeOf<RunOutcome | undefined>()
    expectTypeOf(summary.run_outcome_status).toEqualTypeOf<
      RunOutcome['status'] | undefined
    >()
    expectTypeOf(summary.underlying_outcome).toEqualTypeOf<
      RunOutcome | undefined
    >()
    expect(dutStatus).toBe('interrupted')
  })

  it('keeps the OpenBMC core dump contract metadata-only', () => {
    expectTypeOf(
      coreDumpHandoff.analyzer.automatic_upload,
    ).toEqualTypeOf<false>()
    expectTypeOf(
      coreDumpHandoff.core_dumps[0].handoff.upload_performed,
    ).toEqualTypeOf<false>()
    expect(coreDumpHandoff.core_dumps[0].handoff.action).toBe('manual_upload')
  })

  it('types identity as a required part of only the 1.1 canonical result', () => {
    expectTypeOf<Manifest['run_identity']>().toEqualTypeOf<RunIdentity | undefined>()
    expectTypeOf<CollectionSummary['run_identity']>().toEqualTypeOf<RunIdentity | undefined>()
    expectTypeOf<Extract<RunResult, { schema_version: '1.1' }>['run_identity']>()
      .toEqualTypeOf<RunIdentity>()
    expectTypeOf<RunIdentity['output']['caller_relation']>()
      .toEqualTypeOf<'absent' | 'same' | 'descendant'>()
    expectTypeOf<RunIdentity['catalog']['binding']>()
      .toEqualTypeOf<'manifest_bound' | 'operator_supplied' | 'discovered'>()
  })
})

describe('manifest report metadata types', () => {
  it('exposes additive platform, security, component, and access metadata', () => {
    const platformIdentity: PlatformIdentity = {
      baseboard: 'VR-NVL72',
      node_type: 'compute',
      model: 'DGX GB300',
      part_number: null,
      serial_number: null,
    }
    const securityMode: SecurityModeMetadata = {
      status: 'reported',
      value: 'production',
      source: 'dut_config.security_mode',
    }
    const accessPath: AccessPath = 'host_ssh'

    expectTypeOf<DUT['platform_identity']>().toEqualTypeOf<PlatformIdentity | undefined>()
    expectTypeOf<DUT['security_mode']>().toEqualTypeOf<SecurityModeMetadata | undefined>()
    expectTypeOf<DUT['collector_groups'][number]['component_labels']>().toEqualTypeOf<string[] | undefined>()
    expectTypeOf<DUT['collector_groups'][number]['access_path']>().toEqualTypeOf<AccessPath | undefined>()
    expectTypeOf<DUT['collector_groups'][number]['collectors'][number]['component_label']>().toEqualTypeOf<string | undefined>()
    expectTypeOf<FileEntry['access_path']>().toEqualTypeOf<AccessPath | undefined>()
    expect(platformIdentity.baseboard).toBe('VR-NVL72')
    expect(securityMode.source).toBe('dut_config.security_mode')
    expect(accessPath).toBe('host_ssh')
  })
})
