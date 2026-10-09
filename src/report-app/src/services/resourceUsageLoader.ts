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

import type { ResourceLoadDiagnostics, ResourceSamplePoint } from '@/types/resourceUsage'
import { emptyResourceDiagnostics, normalizeResourceSample } from '@/utils/resourceUsage'

export const RESOURCE_USAGE_PATH = '.metadata/resource_usage.json'
export const RESOURCE_CURRENT_SAMPLES_PATH = '.metadata/resource_usage_samples.jsonl'
export const RESOURCE_PREVIOUS_SAMPLES_PATH = '.metadata/resource_usage_samples.previous.jsonl'

const CHUNK_BYTES = 256 * 1024
const MAX_MAIN_ARTIFACT_BYTES = 4 * 1024 * 1024
const MAX_HISTORY_BYTES = 64 * 1024 * 1024
const MAX_SAMPLE_LINE_BYTES = 1024 * 1024
const MAX_LOADED_SAMPLES = 20_000
const MAX_HISTORY_SEGMENTS = 2
const HISTORY_PATHS = new Map([
  ['resource_usage_samples.previous.jsonl', RESOURCE_PREVIOUS_SAMPLES_PATH],
  ['resource_usage_samples.jsonl', RESOURCE_CURRENT_SAMPLES_PATH],
])

type JsonRecord = Record<string, unknown>

export interface ResourceFileAccess {
  mode: 'http' | 'file'
  fileMap?: Map<string, File>
  fetcher?: typeof fetch
  signal?: AbortSignal
}

export interface LoadedResourceUsage {
  artifact: JsonRecord
  samples: ResourceSamplePoint[]
  diagnostics: ResourceLoadDiagnostics
}

export interface LoadedResourceUsageSummary {
  artifact: JsonRecord
  samples: ResourceSamplePoint[]
  diagnostics: ResourceLoadDiagnostics
}

export class ResourceArtifactMissingError extends Error {
  constructor(message = 'Resource telemetry artifact is not present in this run.') {
    super(message)
    this.name = 'ResourceArtifactMissingError'
  }
}

export class ResourceArtifactInvalidError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ResourceArtifactInvalidError'
  }
}

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function nonNegativeInteger(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0
}

function throwIfAborted(signal?: AbortSignal): void {
  signal?.throwIfAborted()
}

function artifactUrl(path: string): string {
  return `../${path.split('/').map(encodeURIComponent).join('/')}`
}

async function* fileChunks(file: File, signal?: AbortSignal): AsyncGenerator<Uint8Array> {
  throwIfAborted(signal)
  for (let offset = 0; offset < file.size; offset += CHUNK_BYTES) {
    throwIfAborted(signal)
    const buffer = await file.slice(offset, Math.min(file.size, offset + CHUNK_BYTES)).arrayBuffer()
    throwIfAborted(signal)
    yield new Uint8Array(buffer)
  }
}

async function* responseChunks(response: Response, signal?: AbortSignal): AsyncGenerator<Uint8Array> {
  if (!response.body) {
    throw new ResourceArtifactInvalidError('The browser did not provide a streaming response for this resource artifact.')
  }
  const reader = response.body.getReader()
  try {
    while (true) {
      throwIfAborted(signal)
      const chunk = await reader.read()
      throwIfAborted(signal)
      if (chunk.done) break
      if (chunk.value) yield chunk.value
    }
  } finally {
    await reader.cancel().catch(() => undefined)
  }
}

async function openChunks(path: string, access: ResourceFileAccess): Promise<AsyncGenerator<Uint8Array>> {
  throwIfAborted(access.signal)
  if (access.mode === 'file') {
    const file = access.fileMap?.get(path)
    if (!file) throw new ResourceArtifactMissingError(`File not found in selected run: ${path}`)
    return fileChunks(file, access.signal)
  }
  const fetcher = access.fetcher ?? fetch
  const response = access.signal
    ? await fetcher(artifactUrl(path), { signal: access.signal })
    : await fetcher(artifactUrl(path))
  throwIfAborted(access.signal)
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined)
    throw new ResourceArtifactMissingError(`Artifact not found: ${path}`)
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined)
    throw new Error(`Failed to load ${path}: HTTP ${response.status} ${response.statusText}`)
  }
  return responseChunks(response, access.signal)
}

function parseContentLength(response: Response): number | null {
  const raw = response.headers.get('content-length')
  if (raw === null || !/^\d+$/.test(raw)) return null
  const parsed = Number(raw)
  return Number.isSafeInteger(parsed) ? parsed : null
}

function summaryLimitError(): ResourceArtifactInvalidError {
  return new ResourceArtifactInvalidError(
    `Resource telemetry summary exceeds the ${MAX_MAIN_ARTIFACT_BYTES}-byte safety limit.`,
  )
}

async function readBoundedJson(path: string, access: ResourceFileAccess, diagnostics: ResourceLoadDiagnostics): Promise<JsonRecord> {
  diagnostics.filesAttempted.push(path)
  const parts: Uint8Array[] = []
  let bytes = 0

  if (access.mode === 'file') {
    const file = access.fileMap?.get(path)
    if (!file) throw new ResourceArtifactMissingError(`File not found in selected run: ${path}`)
    if (file.size > MAX_MAIN_ARTIFACT_BYTES) {
      diagnostics.mainArtifactTruncated = true
      throw summaryLimitError()
    }
    for await (const chunk of fileChunks(file, access.signal)) {
      throwIfAborted(access.signal)
      // file.size was checked before the first slice, so every requested end
      // offset is within both the actual file and the fixed summary budget.
      bytes += chunk.byteLength
      diagnostics.bytesRead += chunk.byteLength
      parts.push(chunk.slice())
    }
  } else {
    const fetcher = access.fetcher ?? fetch
    const response = access.signal
      ? await fetcher(artifactUrl(path), { signal: access.signal })
      : await fetcher(artifactUrl(path))
    throwIfAborted(access.signal)
    if (response.status === 404) {
      await response.body?.cancel().catch(() => undefined)
      throw new ResourceArtifactMissingError(`Artifact not found: ${path}`)
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined)
      throw new Error(`Failed to load ${path}: HTTP ${response.status} ${response.statusText}`)
    }
    if (!response.body) {
      throw new ResourceArtifactInvalidError('The browser did not provide a streaming response for this resource artifact.')
    }

    const declaredBytes = parseContentLength(response)
    if (declaredBytes !== null && declaredBytes > MAX_MAIN_ARTIFACT_BYTES) {
      diagnostics.mainArtifactTruncated = true
      await response.body.cancel().catch(() => undefined)
      throw summaryLimitError()
    }

    const reader = response.body.getReader()
    try {
      while (true) {
        throwIfAborted(access.signal)
        const chunk = await reader.read()
        throwIfAborted(access.signal)
        if (chunk.done) break
        if (!chunk.value || chunk.value.byteLength === 0) continue

        const remaining = MAX_MAIN_ARTIFACT_BYTES - bytes
        if (remaining <= 0) {
          diagnostics.mainArtifactTruncated = true
          throw summaryLimitError()
        }
        const accepted = chunk.value.byteLength > remaining
          ? chunk.value.subarray(0, remaining)
          : chunk.value
        bytes += accepted.byteLength
        diagnostics.bytesRead += accepted.byteLength
        parts.push(accepted.slice())

        if (chunk.value.byteLength > remaining) {
          diagnostics.mainArtifactTruncated = true
          throw summaryLimitError()
        }
        if (bytes === MAX_MAIN_ARTIFACT_BYTES) {
          // With an exact Content-Length the browser transport has already
          // framed the complete response. For an unframed stream, stop at the
          // ceiling rather than issuing another read merely to probe for EOF.
          if (declaredBytes === MAX_MAIN_ARTIFACT_BYTES) break
          diagnostics.mainArtifactTruncated = true
          throw summaryLimitError()
        }
      }
    } finally {
      await reader.cancel().catch(() => undefined)
    }
  }

  throwIfAborted(access.signal)
  const encoded = new Uint8Array(bytes)
  let offset = 0
  for (const part of parts) {
    encoded.set(part, offset)
    offset += part.byteLength
  }
  const text = new TextDecoder().decode(encoded)
  diagnostics.filesLoaded.push(path)
  try {
    const parsed = JSON.parse(text)
    const record = asRecord(parsed)
    if (Object.keys(record).length === 0) throw new Error('root must be an object')
    return record
  } catch (error) {
    throw new ResourceArtifactInvalidError(`Resource telemetry summary is malformed JSON: ${error}`)
  }
}

interface HistoryBudget {
  bytes: number
  samples: number
}

interface HistorySegment {
  path: string
  expected: boolean
}

async function readHistorySegment(
  path: string,
  access: ResourceFileAccess,
  diagnostics: ResourceLoadDiagnostics,
  budget: HistoryBudget,
  sampleLimit: number,
  destination: ResourceSamplePoint[],
): Promise<void> {
  throwIfAborted(access.signal)
  diagnostics.filesAttempted.push(path)
  let chunks: AsyncGenerator<Uint8Array>
  try {
    chunks = await openChunks(path, access)
  } catch (error) {
    if (error instanceof ResourceArtifactMissingError) {
      diagnostics.missingFiles.push(path)
      return
    }
    throw error
  }

  diagnostics.filesLoaded.push(path)
  const decoder = new TextDecoder()
  let lineParts: Uint8Array[] = []
  let lineBytes = 0
  let droppingOversizedLine = false
  let stopped = false

  const resetLine = () => {
    lineParts = []
    lineBytes = 0
  }

  const consumeLine = (): boolean => {
    if (lineBytes === 0) return false
    const encoded = new Uint8Array(lineBytes)
    let offset = 0
    for (const part of lineParts) {
      encoded.set(part, offset)
      offset += part.byteLength
    }
    resetLine()
    const line = decoder.decode(encoded).trim()
    if (!line) return false
    try {
      const sample = normalizeResourceSample(JSON.parse(line))
      if (!sample) {
        diagnostics.malformedLines++
        return false
      }
      if (budget.samples >= sampleLimit) {
        diagnostics.sampleLimitReached = true
        return true
      }
      destination.push(sample)
      budget.samples++
    } catch {
      diagnostics.malformedLines++
    }
    return false
  }

  const appendLineBytes = (part: Uint8Array) => {
    if (droppingOversizedLine || part.byteLength === 0) return
    if (lineBytes + part.byteLength > MAX_SAMPLE_LINE_BYTES) {
      diagnostics.oversizedLines++
      resetLine()
      droppingOversizedLine = true
      return
    }
    // Copy the view so a large network chunk cannot remain retained through a
    // tiny subarray while the next chunk is awaited.
    lineParts.push(part.slice())
    lineBytes += part.byteLength
  }

  for await (const chunk of chunks) {
    throwIfAborted(access.signal)
    const remainingBytes = MAX_HISTORY_BYTES - budget.bytes
    if (remainingBytes <= 0) {
      diagnostics.byteLimitReached = true
      break
    }
    const boundedChunk = chunk.byteLength > remainingBytes
      ? chunk.subarray(0, remainingBytes)
      : chunk
    budget.bytes += boundedChunk.byteLength
    diagnostics.bytesRead += boundedChunk.byteLength
    // Stop as soon as the aggregate ceiling is filled. Waiting for another
    // iterator result just to prove that more data exists would itself read a
    // chunk beyond the safety budget.
    const reachedByteLimit = boundedChunk.byteLength < chunk.byteLength
      || budget.bytes >= MAX_HISTORY_BYTES
    let lineStart = 0
    for (let index = 0; index < boundedChunk.byteLength; index++) {
      if (boundedChunk[index] !== 0x0a) continue
      appendLineBytes(boundedChunk.subarray(lineStart, index))
      if (droppingOversizedLine) {
        droppingOversizedLine = false
      } else {
        stopped = consumeLine()
      }
      lineStart = index + 1
      if (stopped) break
    }
    if (!stopped) appendLineBytes(boundedChunk.subarray(lineStart))
    if (reachedByteLimit) diagnostics.byteLimitReached = true
    if (diagnostics.byteLimitReached || stopped) break
  }

  throwIfAborted(access.signal)
  if (!diagnostics.byteLimitReached && !stopped && !droppingOversizedLine) {
    consumeLine()
  }
}

function historySegments(
  artifact: JsonRecord,
  diagnostics: ResourceLoadDiagnostics,
): HistorySegment[] {
  const history = asRecord(artifact.sample_history)
  const configuredRaw = asArray(history.segments)
  const configured: Array<{ role: string; path: string; expected: boolean }> = []
  const seen = new Set<string>()
  for (const segment of configuredRaw) {
    const record = asRecord(segment)
    const name = typeof record.path === 'string' ? record.path : ''
    const role = typeof record.role === 'string' ? record.role : ''
    const basename = name.replace(/\\/g, '/').split('/').filter(Boolean).pop() ?? ''
    const path = HISTORY_PATHS.get(basename) ?? ''
    if (!path || seen.has(path) || configured.length >= MAX_HISTORY_SEGMENTS) {
      diagnostics.historySegmentsIgnored++
      continue
    }
    seen.add(path)
    configured.push({ role, path, expected: nonNegativeInteger(record.samples) > 0 })
  }
  if (configuredRaw.length > 0) {
    return configured
      .sort((left, right) => (left.role === 'previous' ? -1 : right.role === 'previous' ? 1 : 0))
      .map(({ path, expected }) => ({ path, expected }))
  }
  const hasHistoryMetadata = Object.keys(history).length > 0
  const retained = nonNegativeInteger(history.samples_retained)
  return [
    { path: RESOURCE_PREVIOUS_SAMPLES_PATH, expected: false },
    { path: RESOURCE_CURRENT_SAMPLES_PATH, expected: hasHistoryMetadata && retained > 0 },
  ]
}

function sampleKey(sample: ResourceSamplePoint): string {
  return `${sample.timestamp ?? ''}:${sample.elapsedSeconds ?? ''}`
}

function summaryFallbackSamples(artifact: JsonRecord): ResourceSamplePoint[] {
  const samples: ResourceSamplePoint[] = []
  const seen = new Set<string>()
  for (const raw of [artifact.baseline, artifact.latest]) {
    const sample = normalizeResourceSample(raw)
    if (!sample) continue
    const key = sampleKey(sample)
    if (seen.has(key)) continue
    samples.push(sample)
    seen.add(key)
  }
  return samples
}

function addSummaryFallbackSamples(
  fallbackSamples: ResourceSamplePoint[],
  samples: ResourceSamplePoint[],
): number {
  const protectedSamples = new Set<ResourceSamplePoint>()
  const missing: ResourceSamplePoint[] = []
  for (const fallback of fallbackSamples) {
    const existing = samples.find(sample => sampleKey(sample) === sampleKey(fallback))
    if (existing) protectedSamples.add(existing)
    else missing.push(fallback)
  }

  let removed = 0
  let overflow = Math.max(0, samples.length + missing.length - MAX_LOADED_SAMPLES)
  for (let index = 0; overflow > 0 && index < samples.length;) {
    if (protectedSamples.has(samples[index])) {
      index++
      continue
    }
    samples.splice(index, 1)
    overflow--
    removed++
  }
  samples.push(...missing.slice(0, MAX_LOADED_SAMPLES - samples.length))
  return removed
}

/**
 * Load only the bounded resource summary artifact.
 *
 * Dashboard callers deliberately use this entry point so rendering a small
 * overview can never open either JSONL history segment or spend the separate
 * history byte/sample budgets used by the detailed analysis page.
 */
export async function loadResourceUsageSummary(
  access: ResourceFileAccess,
): Promise<LoadedResourceUsageSummary> {
  const diagnostics = emptyResourceDiagnostics()
  const artifact = await readBoundedJson(RESOURCE_USAGE_PATH, access, diagnostics)
  return { artifact, samples: summaryFallbackSamples(artifact), diagnostics }
}

export async function loadResourceUsageArtifacts(access: ResourceFileAccess): Promise<LoadedResourceUsage> {
  const diagnostics = emptyResourceDiagnostics()
  diagnostics.historySamplesLoaded = 0
  const artifact = await readBoundedJson(RESOURCE_USAGE_PATH, access, diagnostics)
  const fallbackSamples = summaryFallbackSamples(artifact)
  const segments = historySegments(artifact, diagnostics)
  const samplesByPath = new Map<string, ResourceSamplePoint[]>()
  const budget: HistoryBudget = { bytes: 0, samples: 0 }

  // Prioritize the current segment while enforcing one shared byte/sample
  // budget. Results are assembled in chronological segment order below. This
  // keeps recent evidence when an oversized previous segment would otherwise
  // exhaust the fixed sample ceiling first.
  const loadingSegments = [...segments].sort((left, right) => (
    left.path === RESOURCE_CURRENT_SAMPLES_PATH
      ? -1
      : right.path === RESOURCE_CURRENT_SAMPLES_PATH
        ? 1
        : 0
  ))
  for (let index = 0; index < loadingSegments.length; index++) {
    const segment = loadingSegments[index]
    const destination: ResourceSamplePoint[] = []
    samplesByPath.set(segment.path, destination)
    const missingBefore = diagnostics.missingFiles.length
    await readHistorySegment(segment.path, access, diagnostics, budget, MAX_LOADED_SAMPLES, destination)
    if (!segment.expected && diagnostics.missingFiles.length > missingBefore) {
      diagnostics.missingFiles.pop()
    }
    if (diagnostics.byteLimitReached) break
    if (budget.samples >= MAX_LOADED_SAMPLES) {
      if (loadingSegments.slice(index + 1).some(candidate => candidate.expected)) {
        diagnostics.sampleLimitReached = true
      }
      break
    }
  }

  const samples = segments.flatMap(segment => samplesByPath.get(segment.path) ?? [])
  const historySamplesReplaced = addSummaryFallbackSamples(fallbackSamples, samples)
  diagnostics.historySamplesLoaded = budget.samples - historySamplesReplaced
  if (historySamplesReplaced > 0) {
    diagnostics.sampleLimitReached = true
  }
  return { artifact, samples, diagnostics }
}
