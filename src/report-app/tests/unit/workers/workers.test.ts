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

import { describe, expect, it, vi } from 'vitest'
import { handleMessage as parseFile } from '@/workers/fileParser.worker'
import { handleMessage as parseJson } from '@/workers/jsonParser.worker'
import { handleMessage as analyzeLog } from '@/workers/logAnalyzer.worker'
import { handleMessage as searchContent } from '@/workers/searchIndex.worker'

describe('report worker handlers', () => {
  it('indexes exact line boundaries including trailing and empty content', () => {
    expect(parseFile({ content: 'alpha\nbeta\n', chunkSize: 2 })).toEqual({
      lineCount: 3,
      lineOffsets: [0, 6, 11],
      complete: true,
    })
    expect(parseFile({ content: '' })).toEqual({
      lineCount: 1,
      lineOffsets: [0],
      complete: true,
    })
  })

  it('returns parsed JSON or a bounded error representation', () => {
    expect(parseJson({ content: '{"ok":true}' })).toEqual({ data: { ok: true } })
    expect(parseJson({ content: '{broken' })).toMatchObject({
      data: null,
      error: expect.any(String),
    })

    const parseSpy = vi.spyOn(JSON, 'parse').mockImplementationOnce(() => {
      throw 'non-error failure'
    })
    expect(parseJson({ content: 'ignored' })).toEqual({
      data: null,
      error: 'non-error failure',
    })
    parseSpy.mockRestore()
  })

  it('extracts sorted log levels, components, and severity counts', () => {
    const result = analyzeLog({
      content: [
        '[2026-08-19] [WARNING] [Zeta] warm',
        '[2026-08-19] [ERROR] [Alpha] failed',
        '[2026-08-19] [INFO] [Alpha] ready',
        'unstructured line',
      ].join('\n'),
    })

    expect(result).toEqual({
      levels: ['ERROR', 'INFO', 'WARNING'],
      components: ['Alpha', 'Zeta'],
      lineCount: 4,
      errorCount: 1,
      warnCount: 1,
    })
  })

  it('searches literal text case-insensitively with line metadata', () => {
    const longLine = `prefix ${'x'.repeat(220)} Needle suffix`
    const result = searchContent({
      content: `first NEEDLE\nmiss\n${longLine}`,
      query: 'needle',
      filePath: 'dut-a/system.log',
    })

    expect(result.results).toHaveLength(2)
    expect(result.results[0]).toEqual({
      filePath: 'dut-a/system.log',
      lineNumber: 1,
      lineContent: 'first NEEDLE',
      matchStart: 6,
      matchEnd: 12,
    })
    expect(result.results[1].lineContent).toHaveLength(200)
  })

  it('supports reviewed regular expressions and rejects nonmatches', () => {
    const result = searchContent({
      content: 'GPU 0 failed\nGPU healthy\nGPU 12 failed',
      query: 'GPU \\d+ failed',
      filePath: 'dut-a/gpu.log',
      regex: true,
    })

    expect(result.results.map(match => match.lineNumber)).toEqual([1, 3])
    expect(result.results.map(match => [match.matchStart, match.matchEnd]))
      .toEqual([[0, 12], [0, 13]])
  })
})
