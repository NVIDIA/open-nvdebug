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
import resourceArtifact from '../../fixtures/resource_usage.json'
import previousSamples from '../../fixtures/resource_usage_samples.previous.jsonl?raw'
import currentSamples from '../../fixtures/resource_usage_samples.jsonl?raw'
import {
  RESOURCE_CURRENT_SAMPLES_PATH,
  RESOURCE_PREVIOUS_SAMPLES_PATH,
  RESOURCE_USAGE_PATH,
  ResourceArtifactInvalidError,
  ResourceArtifactMissingError,
  loadResourceUsageArtifacts,
  loadResourceUsageSummary,
} from '@/services/resourceUsageLoader'

function fixtureFiles(current = currentSamples, includePrevious = true): Map<string, File> {
  const files = new Map<string, File>([
    [RESOURCE_USAGE_PATH, new File([JSON.stringify(resourceArtifact)], 'resource_usage.json')],
    [RESOURCE_CURRENT_SAMPLES_PATH, new File([current], 'resource_usage_samples.jsonl')],
  ])
  if (includePrevious) {
    files.set(RESOURCE_PREVIOUS_SAMPLES_PATH, new File([previousSamples], 'resource_usage_samples.previous.jsonl'))
  }
  return files
}

function sampleLines(start: number, count: number): string {
  return Array.from({ length: count }, (_, offset) => JSON.stringify({
    elapsed_seconds: start + offset,
    process: { rss_bytes: start + offset },
  })).join('\n')
}

describe('resource usage loader', () => {
  it('loads the dashboard summary without opening either history artifact', async () => {
    const historyFile = {
      size: 1,
      slice: vi.fn(() => {
        throw new Error('history must not be opened by the summary loader')
      }),
    } as unknown as File
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([JSON.stringify(resourceArtifact)], 'resource_usage.json')],
      [RESOURCE_CURRENT_SAMPLES_PATH, historyFile],
      [RESOURCE_PREVIOUS_SAMPLES_PATH, historyFile],
    ])

    const loaded = await loadResourceUsageSummary({ mode: 'file', fileMap: files })

    expect(loaded.artifact.schema_version).toBe(resourceArtifact.schema_version)
    expect(loaded.diagnostics.filesAttempted).toEqual([RESOURCE_USAGE_PATH])
    expect(loaded.diagnostics.filesLoaded).toEqual([RESOURCE_USAGE_PATH])
    expect(loaded.diagnostics.historySamplesLoaded).toBeNull()
    expect(loaded.samples.map(sample => sample.elapsedSeconds)).toEqual([0, 60])
    expect(loaded.samples[1].cpuPressureSomeAvg10).toBe(1.25)
    expect(historyFile.slice).not.toHaveBeenCalled()
  })

  it('uses one bounded HTTP request for the dashboard summary', async () => {
    const controller = new AbortController()
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe(`../${RESOURCE_USAGE_PATH}`)
      expect(init?.signal).toBe(controller.signal)
      return new Response(JSON.stringify(resourceArtifact), { status: 200 })
    })

    await loadResourceUsageSummary({
      mode: 'http',
      fetcher: fetcher as typeof fetch,
      signal: controller.signal,
    })

    expect(fetcher).toHaveBeenCalledOnce()
  })

  it('rejects an oversized file before requesting any slice or consulting history', async () => {
    const maximum = 4 * 1024 * 1024
    const huge = {
      size: maximum + 1,
      slice: vi.fn(),
    } as unknown as File
    const historyFile = { size: 1, slice: vi.fn() } as unknown as File

    await expect(loadResourceUsageSummary({
      mode: 'file',
      fileMap: new Map([
        [RESOURCE_USAGE_PATH, huge],
        [RESOURCE_CURRENT_SAMPLES_PATH, historyFile],
      ]),
    })).rejects.toBeInstanceOf(ResourceArtifactInvalidError)
    expect(huge.slice).not.toHaveBeenCalled()
    expect(historyFile.slice).not.toHaveBeenCalled()
  })

  it('reads an exact 4 MiB file without any slice extending past the budget', async () => {
    const maximum = 4 * 1024 * 1024
    const chunkBytes = 256 * 1024
    const prefix = '{"padding":"'
    const suffix = '"}'
    const exact = new File(
      [prefix, 'x'.repeat(maximum - prefix.length - suffix.length), suffix],
      'resource_usage.json',
    )
    const slice = vi.spyOn(exact, 'slice')

    const loaded = await loadResourceUsageSummary({
      mode: 'file',
      fileMap: new Map([[RESOURCE_USAGE_PATH, exact]]),
    })

    expect(loaded.diagnostics.bytesRead).toBe(maximum)
    expect(slice).toHaveBeenCalledTimes(maximum / chunkBytes)
    expect(slice).toHaveBeenLastCalledWith(maximum - chunkBytes, maximum)
    expect(slice.mock.calls.every(([, end]) => typeof end === 'number' && end <= maximum)).toBe(true)
  })

  it('accepts an exact framed 4 MiB HTTP summary and stops at the declared boundary', async () => {
    const maximum = 4 * 1024 * 1024
    const prefix = '{"padding":"'
    const suffix = '"}'
    const encoded = new TextEncoder().encode(
      `${prefix}${'x'.repeat(maximum - prefix.length - suffix.length)}${suffix}`,
    )
    const fetcher = vi.fn(async () => new Response(encoded, {
      status: 200,
      headers: { 'content-length': String(maximum) },
    }))

    const loaded = await loadResourceUsageSummary({
      mode: 'http',
      fetcher: fetcher as typeof fetch,
    })

    expect(loaded.diagnostics.bytesRead).toBe(maximum)
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it('retains only the remaining HTTP bytes and cancels an over-budget stream', async () => {
    const maximum = 4 * 1024 * 1024
    const first = new Uint8Array(maximum - 5).fill(0x78)
    const tail = new Uint8Array(10).fill(0x79)
    const tailSubarray = vi.spyOn(tail, 'subarray')
    let cancelled = false
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(first)
        controller.enqueue(tail)
      },
      cancel() { cancelled = true },
    })
    const fetcher = vi.fn(async () => new Response(stream, { status: 200 }))

    await expect(loadResourceUsageSummary({
      mode: 'http',
      fetcher: fetcher as typeof fetch,
    })).rejects.toBeInstanceOf(ResourceArtifactInvalidError)

    expect(tailSubarray).toHaveBeenCalledWith(0, 5)
    expect(cancelled).toBe(true)
  })

  it('honors aborts while reading the dashboard summary from a file', async () => {
    const controller = new AbortController()
    const encoded = new TextEncoder().encode(JSON.stringify(resourceArtifact))
    const bytes = encoded.buffer.slice(
      encoded.byteOffset,
      encoded.byteOffset + encoded.byteLength,
    ) as ArrayBuffer
    const abortingFile = {
      size: encoded.byteLength,
      slice: vi.fn(() => ({
        arrayBuffer: vi.fn(async () => {
          controller.abort()
          return bytes
        }),
      })),
    } as unknown as File

    await expect(loadResourceUsageSummary({
      mode: 'file',
      fileMap: new Map([[RESOURCE_USAGE_PATH, abortingFile]]),
      signal: controller.signal,
    })).rejects.toMatchObject({ name: 'AbortError' })
    expect(abortingFile.slice).toHaveBeenCalledOnce()
  })

  it('streams the summary and ordered JSONL segments from an offline directory', async () => {
    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: fixtureFiles() })

    expect(loaded.samples.map(sample => sample.elapsedSeconds)).toEqual([0, 20, 40, 60])
    expect(loaded.diagnostics.filesLoaded).toEqual([
      RESOURCE_USAGE_PATH,
      RESOURCE_CURRENT_SAMPLES_PATH,
      RESOURCE_PREVIOUS_SAMPLES_PATH,
    ])
    expect(loaded.diagnostics.bytesRead).toBeGreaterThan(0)
    expect(loaded.diagnostics.historySamplesLoaded).toBe(4)
    expect(loaded.diagnostics.malformedLines).toBe(0)
  })

  it('skips malformed JSONL without discarding valid surrounding samples', async () => {
    const loaded = await loadResourceUsageArtifacts({
      mode: 'file',
      fileMap: fixtureFiles(`${currentSamples.trim()}\n{not-json}\n`),
    })

    expect(loaded.samples).toHaveLength(4)
    expect(loaded.diagnostics.malformedLines).toBe(1)
  })

  it('drops an oversized JSONL line and resumes at the next newline', async () => {
    const oversized = 'x'.repeat(1024 * 1024 + 1)
    const loaded = await loadResourceUsageArtifacts({
      mode: 'file',
      fileMap: fixtureFiles(`${oversized}\n${currentSamples}`),
    })

    expect(loaded.samples).toHaveLength(4)
    expect(loaded.diagnostics.oversizedLines).toBe(1)
  })

  it('never consumes or counts history bytes past the aggregate 64 MiB ceiling', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.sample_history.segments = [{
      role: 'current',
      path: 'resource_usage_samples.jsonl',
      samples: 1,
    }]
    const summary = JSON.stringify(artifact)
    const chunkBytes = 256 * 1024
    const historyBytes = 64 * 1024 * 1024 + 17
    const reusableChunk = new Uint8Array(chunkBytes).fill(0x78)
    const historyFile = {
      size: historyBytes,
      slice: vi.fn((start: number, end: number) => ({
        arrayBuffer: vi.fn(async () => {
          const length = end - start
          const bytes = length === chunkBytes ? reusableChunk : reusableChunk.subarray(0, length)
          return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
        }),
      })),
    } as unknown as File
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([summary], 'resource_usage.json')],
      [RESOURCE_CURRENT_SAMPLES_PATH, historyFile],
    ])

    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: files })

    expect(loaded.diagnostics.byteLimitReached).toBe(true)
    expect(loaded.diagnostics.bytesRead).toBe(new TextEncoder().encode(summary).byteLength + 64 * 1024 * 1024)
    expect(loaded.diagnostics.historySamplesLoaded).toBe(0)
    expect(historyFile.slice).toHaveBeenCalledTimes(256)
    expect(historyFile.slice).toHaveBeenLastCalledWith(64 * 1024 * 1024 - chunkBytes, 64 * 1024 * 1024)
  })

  it('enforces the line ceiling in encoded bytes rather than UTF-16 characters', async () => {
    const oversizedMultibyte = 'é'.repeat(600_000)
    const loaded = await loadResourceUsageArtifacts({
      mode: 'file',
      fileMap: fixtureFiles(`${oversizedMultibyte}\n${currentSamples}`),
    })

    expect(loaded.samples).toHaveLength(4)
    expect(loaded.diagnostics.oversizedLines).toBe(1)
    expect(loaded.diagnostics.malformedLines).toBe(0)
  })

  it('stops parsing at the fixed sample ceiling', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.sample_history.segments = [{ role: 'current', path: 'resource_usage_samples.jsonl', samples: 20005 }]
    artifact.baseline = null
    artifact.latest = null
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([JSON.stringify(artifact)], 'resource_usage.json')],
      [RESOURCE_CURRENT_SAMPLES_PATH, new File([sampleLines(0, 20005)], 'resource_usage_samples.jsonl')],
    ])

    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: files })

    expect(loaded.samples).toHaveLength(20000)
    expect(loaded.diagnostics.sampleLimitReached).toBe(true)
  })

  it('does not claim truncation when exactly the sample ceiling reaches EOF', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.sample_history.segments = [{ role: 'current', path: 'resource_usage_samples.jsonl', samples: 20000 }]
    artifact.baseline = { elapsed_seconds: 0, process: { rss_bytes: 0 } }
    artifact.latest = { elapsed_seconds: 19999, process: { rss_bytes: 19999 } }
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([JSON.stringify(artifact)], 'resource_usage.json')],
      [RESOURCE_CURRENT_SAMPLES_PATH, new File([`${sampleLines(0, 20000)}\n`], 'resource_usage_samples.jsonl')],
    ])

    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: files })

    expect(loaded.samples).toHaveLength(20000)
    expect(loaded.diagnostics.sampleLimitReached).toBe(false)
  })

  it('retains current history plus baseline/latest when an oversized previous segment exceeds the ceiling', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.sample_history.segments = [
      { role: 'previous', path: 'resource_usage_samples.previous.jsonl', samples: 20005 },
      { role: 'current', path: 'resource_usage_samples.jsonl', samples: 3 },
    ]
    artifact.baseline = { elapsed_seconds: 30000, process: { rss_bytes: 1 } }
    artifact.latest = { elapsed_seconds: 30001, process: { rss_bytes: 2 } }
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([JSON.stringify(artifact)], 'resource_usage.json')],
      [RESOURCE_PREVIOUS_SAMPLES_PATH, new File([sampleLines(0, 20005)], 'resource_usage_samples.previous.jsonl')],
      [RESOURCE_CURRENT_SAMPLES_PATH, new File([sampleLines(20005, 3)], 'resource_usage_samples.jsonl')],
    ])

    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: files })
    const elapsed = loaded.samples.map(sample => sample.elapsedSeconds)

    expect(loaded.samples).toHaveLength(20000)
    expect(loaded.diagnostics.historySamplesLoaded).toBe(19998)
    expect(loaded.diagnostics.sampleLimitReached).toBe(true)
    expect(elapsed.slice(-5)).toEqual([20005, 20006, 20007, 30000, 30001])
    expect(elapsed).not.toContain(0)
    expect(elapsed).not.toContain(1)
  })

  it('streams HTTP artifacts from paths relative to the offline report directory', async () => {
    const payloads: Record<string, string> = {
      [`../${RESOURCE_USAGE_PATH}`]: JSON.stringify(resourceArtifact),
      [`../${RESOURCE_PREVIOUS_SAMPLES_PATH}`]: previousSamples,
      [`../${RESOURCE_CURRENT_SAMPLES_PATH}`]: currentSamples,
    }
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const content = payloads[String(input)]
      return content === undefined ? new Response('', { status: 404 }) : new Response(content, { status: 200 })
    })

    const loaded = await loadResourceUsageArtifacts({
      mode: 'http',
      fetcher: fetcher as typeof fetch,
    })

    expect(loaded.samples).toHaveLength(4)
    expect(fetcher).toHaveBeenCalledWith(`../${RESOURCE_USAGE_PATH}`)
    expect(fetcher).toHaveBeenCalledWith(`../${RESOURCE_CURRENT_SAMPLES_PATH}`)
  })

  it('confines configured history names to the metadata directory', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.sample_history.segments = [{ role: 'current', path: '../../resource_usage_samples.jsonl', samples: 2 }]
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([JSON.stringify(artifact)], 'resource_usage.json')],
      [RESOURCE_CURRENT_SAMPLES_PATH, new File([currentSamples], 'resource_usage_samples.jsonl')],
    ])

    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: files })

    expect(loaded.samples.map(sample => sample.elapsedSeconds)).toEqual([40, 60, 0])
    expect(loaded.diagnostics.filesAttempted).not.toContain('../../resource_usage_samples.jsonl')
  })

  it('bounds and allowlists configured history segments before issuing requests', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.sample_history.segments = [
      { role: 'current', path: 'resource_usage_samples.jsonl', samples: 2 },
      ...Array.from({ length: 5_000 }, (_, index) => ({
        role: 'current',
        path: index % 2 ? `unexpected-${index}.jsonl` : 'resource_usage_samples.jsonl',
        samples: 1,
      })),
    ]
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === `../${RESOURCE_USAGE_PATH}`) return new Response(JSON.stringify(artifact), { status: 200 })
      if (String(input) === `../${RESOURCE_CURRENT_SAMPLES_PATH}`) return new Response(currentSamples, { status: 200 })
      return new Response('', { status: 404 })
    })

    const loaded = await loadResourceUsageArtifacts({ mode: 'http', fetcher: fetcher as typeof fetch })

    expect(loaded.samples.map(sample => sample.elapsedSeconds)).toEqual([40, 60, 0])
    expect(loaded.diagnostics.historySegmentsIgnored).toBe(5_000)
    expect(fetcher).toHaveBeenCalledTimes(2)
  })

  it('uses baseline/latest fallback without claiming missing history for pre-history artifacts', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    delete artifact.sample_history
    const files = new Map<string, File>([
      [RESOURCE_USAGE_PATH, new File([JSON.stringify(artifact)], 'resource_usage.json')],
    ])

    const loaded = await loadResourceUsageArtifacts({ mode: 'file', fileMap: files })

    expect(loaded.samples.map(sample => sample.elapsedSeconds)).toEqual([0, 60])
    expect(loaded.diagnostics.historySamplesLoaded).toBe(0)
    expect(loaded.diagnostics.missingFiles).toEqual([])
  })

  it('reports a configured, populated history segment as missing', async () => {
    const loaded = await loadResourceUsageArtifacts({
      mode: 'file',
      fileMap: fixtureFiles(currentSamples, false),
    })

    expect(loaded.samples.map(sample => sample.elapsedSeconds)).toEqual([40, 60, 0])
    expect(loaded.diagnostics.missingFiles).toEqual([RESOURCE_PREVIOUS_SAMPLES_PATH])
  })

  it('rejects an oversized summary before parsing it', async () => {
    const huge = new File([`{"padding":"${'x'.repeat(4 * 1024 * 1024)}"}`], 'resource_usage.json')
    await expect(loadResourceUsageArtifacts({
      mode: 'file',
      fileMap: new Map([[RESOURCE_USAGE_PATH, huge]]),
    })).rejects.toBeInstanceOf(ResourceArtifactInvalidError)
  })

  it('uses the dedicated missing-artifact error for legacy runs', async () => {
    await expect(loadResourceUsageArtifacts({ mode: 'file', fileMap: new Map() }))
      .rejects.toBeInstanceOf(ResourceArtifactMissingError)
  })

  it('cancels an HTTP error body before reporting a missing legacy artifact', async () => {
    let cancelled = false
    const fetcher = vi.fn(async () => new Response(new ReadableStream({
      cancel() { cancelled = true },
    }), { status: 404 }))

    await expect(loadResourceUsageArtifacts({ mode: 'http', fetcher: fetcher as typeof fetch }))
      .rejects.toBeInstanceOf(ResourceArtifactMissingError)
    expect(cancelled).toBe(true)
  })

  it('passes an abort signal through HTTP streaming requests', async () => {
    const controller = new AbortController()
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.signal).toBe(controller.signal)
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
      })
    })
    const loading = loadResourceUsageArtifacts({
      mode: 'http',
      fetcher: fetcher as typeof fetch,
      signal: controller.signal,
    })

    controller.abort()

    await expect(loading).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetcher).toHaveBeenCalledWith(`../${RESOURCE_USAGE_PATH}`, { signal: controller.signal })
  })

  it('honors an abort signal while reading file chunks', async () => {
    const controller = new AbortController()
    const encoded = new TextEncoder().encode(JSON.stringify(resourceArtifact))
    const arrayBuffer = encoded.buffer.slice(
      encoded.byteOffset,
      encoded.byteOffset + encoded.byteLength,
    ) as ArrayBuffer
    const abortingFile = {
      size: encoded.byteLength,
      slice: vi.fn(() => ({
        arrayBuffer: vi.fn(async () => {
          controller.abort()
          return arrayBuffer
        }),
      })),
    } as unknown as File

    await expect(loadResourceUsageArtifacts({
      mode: 'file',
      fileMap: new Map([[RESOURCE_USAGE_PATH, abortingFile]]),
      signal: controller.signal,
    })).rejects.toMatchObject({ name: 'AbortError' })
    expect(abortingFile.slice).toHaveBeenCalledOnce()
  })
})
