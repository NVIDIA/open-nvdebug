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

import { afterEach, describe, expect, it, vi } from 'vitest'
import { loadCollectorRuntimeLogs, MAX_RUNTIME_LOG_SCAN_BYTES } from '@/services/collectorRuntimeLogs'
import { MAX_LOG_LINE_CHARACTERS, MAX_LOG_PREVIEW_CHARACTERS, MAX_LOG_PREVIEW_LINES } from '@/utils/logLines'

const path = 'DUT_1/nvdebug_runtime_output.txt'
const entry = (id: string, message: string) => `[2026-09-17 10:00:00.001] [INFO] [CID:${id}] [redfish] ${message}`

function read(content: string, collectorId = 'R1') {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(content)))
  return loadCollectorRuntimeLogs(path, collectorId, { mode: 'http', signal: new AbortController().signal })
}

afterEach(() => vi.unstubAllGlobals())

describe('collector runtime log streaming', () => {
  it('matches exact tags, preserves continuations, and resets at unrelated or untagged records', async () => {
    const expected = [entry('R1', 'first'), 'Traceback:', '  multiline detail', entry('r1', 'last')]
    const result = await read([
      'unowned preamble', entry('R10', 'different collector'), entry('R2', 'mentions [CID:R1]'),
      ...expected.slice(0, 3), '[time] [INFO] [runner] unrelated lifecycle', 'unrelated continuation',
      expected[3], entry('R2', 'other'), 'other continuation',
    ].join('\n'))

    expect(result.content).toBe(expected.join('\n'))
    expect(result.lineCount).toBe(4)
    expect(result.scanLimited).toBe(false)
    expect(result.previewLimited).toBe(false)
    expect(fetch).toHaveBeenCalledWith('../DUT_1/nvdebug_runtime_output.txt', expect.objectContaining({ redirect: 'error' }))
  })

  it.each(['[time] [ERROR] [CID:R2]', '2026-09-17 10:00:00.001 - CID:R2'])('does not inherit collector ownership across a malformed record header: %s', async header => {
    const result = await read([
      entry('R1', 'owned'), header, 'unowned continuation',
    ].join('\n'))
    expect(result.content).toBe(entry('R1', 'owned'))
  })

  it('filters default configured runtime records mixed with canonical lifecycle records', async () => {
    const owned = '2026-09-17 10:00:00.001 - CID:R10] [BaseService - INFO - request started'
    const result = await read([
      '2026-09-17 10:00:00.000 - CID:R100] [BaseService - INFO - unrelated',
      owned, '  continuation',
      '2026-09-17 10:00:00.002 - runner - INFO - mentions CID:R10] [BaseService',
      'unowned continuation',
      '[time] [INFO] [DUT:synthetic] completed',
    ].join('\n'), 'R10')
    expect(result.content).toBe(owned + '\n  continuation')
  })

  it('finds a collector beyond the generic viewer character and line limits', async () => {
    const prefix = `${'x'.repeat(MAX_LOG_PREVIEW_CHARACTERS + 1)}\n` +
      Array.from({ length: MAX_LOG_PREVIEW_LINES + 1 }, () => entry('R2', 'unrelated')).join('\n')
    const progress = vi.fn()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(`${prefix}\n${entry('R1', 'late entry')}`)))
    const result = await loadCollectorRuntimeLogs(path, 'R1', {
      mode: 'http', signal: new AbortController().signal, onProgress: progress,
    })

    expect(result.content).toBe(entry('R1', 'late entry'))
    expect(progress).toHaveBeenLastCalledWith(result.bytesRead)
    expect(progress.mock.calls.length).toBeGreaterThan(1)
  })

  it('reads local streams with split tags, newlines, and UTF-8 characters', async () => {
    const content = entry('R1', 'temperature Δ = 30°C') + '\r\n  detail\r\n' + entry('R2', 'other')
    const bytes = new TextEncoder().encode(content)
    let offset = 0
    const file = { stream: () => new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset < bytes.length) controller.enqueue(bytes.slice(offset, ++offset))
        else controller.close()
      },
    }) } as File
    const result = await loadCollectorRuntimeLogs(path, 'R1', {
      mode: 'file', fileMap: new Map([[path, file]]), signal: new AbortController().signal,
    })
    expect(result.content).toBe(entry('R1', 'temperature Δ = 30°C') + '\n  detail')
    expect(result.bytesRead).toBe(bytes.length)
  })

  it('bounds matching lines and characters, including a single oversized line', async () => {
    const longLine = entry('R1', 'x'.repeat(MAX_LOG_LINE_CHARACTERS * 8))
    const long = await read(longLine)
    expect(long.content.length).toBeLessThan(MAX_LOG_LINE_CHARACTERS + 40)
    expect(long.longLinesTruncated).toBe(true)
    const manyLines = await read(Array.from({ length: MAX_LOG_PREVIEW_LINES + 1 }, () => entry('R1', 'match')).join('\n'))
    expect(manyLines.lineCount).toBe(MAX_LOG_PREVIEW_LINES)
    expect(manyLines.previewLimited).toBe(true)
    const manyCharacters = await read(Array.from({ length: 300 }, () => longLine).join('\n'))
    expect(manyCharacters.content.length).toBeLessThanOrEqual(MAX_LOG_PREVIEW_CHARACTERS)
    expect(manyCharacters.previewLimited).toBe(true)
  })

  it('caps the scan and cancels oversized streams even without a content length', async () => {
    const chunk = new TextEncoder().encode('x'.repeat(1024 * 1024))
    const cancel = vi.fn()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
      pull(controller) { controller.enqueue(chunk) }, cancel,
    }))))
    const result = await loadCollectorRuntimeLogs(path, 'R1', { mode: 'http', signal: new AbortController().signal })
    expect(result.bytesRead).toBe(MAX_RUNTIME_LOG_SCAN_BYTES)
    expect(result.scanLimited).toBe(true)
    expect(result.lineCount).toBe(0)
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('aborts a pending read and releases its stream', async () => {
    const cancel = vi.fn()
    const controller = new AbortController()
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({ cancel }))))
    const pending = loadCollectorRuntimeLogs(path, 'R1', { mode: 'http', signal: controller.signal })
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await Promise.resolve()
    await Promise.resolve()
    controller.abort()
    await rejected
    expect(cancel).toHaveBeenCalledTimes(1)
  })

  it('reports missing files and HTTP failures instead of an empty successful result', async () => {
    await expect(loadCollectorRuntimeLogs(path, 'R1', {
      mode: 'file', fileMap: new Map(), signal: new AbortController().signal,
    })).rejects.toThrow('missing from the selected report folder')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('missing', { status: 404 })))
    await expect(loadCollectorRuntimeLogs(path, 'R1', {
      mode: 'http', signal: new AbortController().signal,
    })).rejects.toThrow('HTTP 404')
  })

  it('rejects traversal paths before reading a log', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    for (const invalid of ['../runtime.txt', 'DUT_1/../runtime.txt', 'DUT_1\\runtime.txt', '/runtime.txt']) {
      await expect(loadCollectorRuntimeLogs(invalid, 'R1', {
        mode: 'http', signal: new AbortController().signal,
      })).rejects.toThrow('path is invalid')
    }
    expect(fetcher).not.toHaveBeenCalled()
  })
})
