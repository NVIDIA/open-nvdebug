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
import type { FileRef } from '@/types/manifest'
import { isDiagnosticFilePath, partitionCollectorFiles } from '@/utils/dedupFiles'

function file(path: string): FileRef {
  return { path, size: 1, type: 'json', collector_id: 'R1' }
}

describe('collector file classification', () => {
  it('recognizes nested diagnostic directories on normalized and Windows paths', () => {
    expect(isDiagnosticFilePath('dut/redfish/R1/diagnostic/request.json')).toBe(true)
    expect(isDiagnosticFilePath(String.raw`dut\redfish\R1\diagnostic\request.json`)).toBe(true)
    expect(isDiagnosticFilePath('dut/redfish/R1/diagnostics/request.json')).toBe(false)
  })

  it('keeps legacy flat diagnostic captures separate from collected artifacts', () => {
    const files = [
      file('dut/redfish/R1/inventory.json'),
      file('dut/redfish/R1/redfish_request_response_log.json'),
      file('dut/redfish/R1/diagnostic_responses_collect.json'),
    ]

    const result = partitionCollectorFiles(files)

    expect(result.artifacts.map(entry => entry.path)).toEqual([
      'dut/redfish/R1/inventory.json',
    ])
    expect(result.diagnostics.map(entry => entry.path)).toEqual([
      'dut/redfish/R1/redfish_request_response_log.json',
      'dut/redfish/R1/diagnostic_responses_collect.json',
    ])
  })
})
