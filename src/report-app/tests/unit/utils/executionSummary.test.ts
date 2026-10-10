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
import { parseExecutionSummary } from '@/utils/executionSummary'

const HEADER = 'Collection Name\tID\tExecution Status\tLog Path\tDuration (s)\tReason\tArtifact Paths\tDiagnostic Paths\tFailure Category'

describe('parseExecutionSummary', () => {
  it('projects canonical TSV rows without changing reason or path text', () => {
    const reason = 'Details: Device Errors: • System_0: - no dump location'
    const result = parseExecutionSummary([
      HEADER,
      `sma_debug_dump\tR39\tError\terror.log\t35.191643\t${reason}\tartifact.json\tdiagnostic.json, error.log\tinternal-error`,
      '',
      'Total execution time: 35.191643s',
    ].join('\n'))

    expect(result.valid).toBe(true)
    expect(result.rows).toHaveLength(1)
    expect(result.rows[0]).toMatchObject({
      collectorId: 'R39',
      reason,
      artifactPaths: ['artifact.json'],
      diagnosticPaths: ['diagnostic.json', 'error.log'],
    })
    expect(result.totalExecutionTime).toBe('Total execution time: 35.191643s')
  })

  it('fails safely when a non-footer row is malformed', () => {
    const result = parseExecutionSummary(`${HEADER}\nnot a tabular row`)
    expect(result.valid).toBe(false)
    expect(result.rows).toEqual([])
    expect(result.error).toContain('malformed row')
  })

  it('fails safely when required columns are absent', () => {
    const result = parseExecutionSummary('Name\tStatus\ncollector\tError')
    expect(result.valid).toBe(false)
    expect(result.error).toContain('missing required columns')
  })

  it('rejects oversized content before creating an unbounded row inventory', () => {
    const result = parseExecutionSummary('x'.repeat(8 * 1024 * 1024 + 1))
    expect(result.valid).toBe(false)
    expect(result.error).toContain('too large')
  })
})
