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

import { describe, expect, it } from 'vitest'
import { systemViewSources, systemViewValue } from '@/utils/systemView'
import type { CollectorResult, DUT, PreflightCheck } from '@/types/manifest'

const collector = {
  id: 'SYNTHETIC_HOST', report_role: 'host_system_snapshot', status: 'skipped',
  reason: 'Host preflight failed: SSH authentication failed',
} as CollectorResult
const dut = { collector_groups: [{ collectors: [collector] }] } as DUT

describe('system view missing-value explanations', () => {
  it('uses the assigned report role and recorded collector outcome', () => {
    const sources = systemViewSources(dut, [])
    expect(systemViewValue(null, 'host.os', sources, [])).toContain('SYNTHETIC_HOST: skipped — Host preflight failed: SSH authentication failed')
    expect(systemViewValue(null, 'bmc.os', sources, [])).toBe('Not collected — no reason was recorded in this report.')
    expect(systemViewValue('Linux', 'host.os', sources, [])).toBe('Linux')
  })

  it('distinguishes a completed source with an absent value from a failed collection', () => {
    const sources = new Map([['host_system_snapshot', [{ ...collector, status: 'success' } as CollectorResult]]])
    expect(systemViewValue('', 'host.kernel', sources, [])).toContain('completed, but this value was not found in the collected output')
    expect(systemViewValue('', 'host.kernel', sources, [])).not.toContain('preflight failed')
  })

  it('gives relevant legacy preflight context without attributing unrelated failures', () => {
    const checks = [{ name: 'HOST', group: 'host', status: 'fail', details: 'Connection timed out' }] as PreflightCheck[]
    expect(systemViewValue(null, 'host.os', new Map(), checks)).toContain('Related preflight failure: HOST — Connection timed out')
    expect(systemViewValue(null, 'bmc.os', new Map(), checks)).toContain('no reason was recorded')
  })

  it('does not invent a failure when the source outcome has no reason', () => {
    const sources = new Map([['host_gpu_runtime', [{ ...collector, status: 'error', reason: '' } as CollectorResult]]])
    expect(systemViewValue(null, 'software.dcgm_version', sources, [])).toContain('error — no reason recorded')
  })
})
