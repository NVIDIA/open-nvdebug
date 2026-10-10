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

import { defineStore } from 'pinia'
import type {
  Manifest,
  DUT,
  FileEntry,
  ErrorEntry,
  CollectorDef,
  CollectionSummary,
  TimingData,
  PreflightData,
  DependencyCheckData,
  ExtensionData,
  OpenBMCCoreDumpManifest,
  OpenBMCCoreDumpRecord,
  RunResult,
  RunIdentity,
  RunPathIdentity,
  CanonicalCollectorCounts,
  CollectorFailureCategory,
  CollectorOutcomeAttribute,
  CollectorOutcomeDetails,
  GranularCollectorTiming,
  TimingReference,
} from '@/types/manifest'
import { SUPPORTED_SCHEMA_VERSIONS } from '@/types/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { normalizeCollectorLifecycleCounts } from '@/utils/collectorLifecycle'
import { normalizeErrorEntries } from '@/utils/errorEntries'
import type { ReportLoadReporter } from '@/services/reportStartup'

declare global {
  interface Window {
    __MANIFEST__?: Manifest
  }
}

const DEFAULT_PRIVACY_NOTICE =
  'Core dumps can contain process memory, credentials, and customer data. ' +
  'This handoff does not upload them to the analyzer. Review the selected ' +
  'file and use the approved analysis destination only when authorized.'

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

async function readTextStreamBounded(
  stream: ReadableStream<Uint8Array>,
  maximumBytes: number,
  expectedBytes: number | null,
  label: string,
  onBytes?: (bytesRead: number) => Promise<void>,
): Promise<string> {
  const reader = stream.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  const chunks: string[] = []
  let bytesRead = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      bytesRead += value.byteLength
      if (bytesRead > maximumBytes) {
        throw new Error(`${label} exceeds the ${maximumBytes}-byte safety limit`)
      }
      chunks.push(decoder.decode(value, { stream: true }))
      await onBytes?.(bytesRead)
    }
    chunks.push(decoder.decode())
  } catch (error) {
    try { await reader.cancel(error) } catch { /* retain the original error */ }
    throw error
  } finally {
    reader.releaseLock()
  }
  if (expectedBytes !== null && bytesRead !== expectedBytes) {
    throw new Error(`${label} size does not match its declaration`)
  }
  return chunks.join('')
}

async function responseJsonBounded(
  response: Response,
  maximumBytes: number,
  label: string,
  reportProgress?: ReportLoadReporter,
): Promise<unknown> {
  if (!response.ok) {
    try { await response.body?.cancel() } catch { /* preserve request failure */ }
    throw new Error(`${label} request failed with HTTP ${response.status}`)
  }
  const contentLength = response.headers.get('content-length')
  let declaredLength: number | null = null
  if (contentLength !== null) {
    const declared = Number(contentLength)
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maximumBytes) {
      try { await response.body?.cancel() } catch { /* preserve bound failure */ }
      throw new Error(`${label} has an invalid or oversized Content-Length`)
    }
    declaredLength = declared
  }
  if (!response.body) {
    if (declaredLength === null) {
      throw new Error(`${label} has no stream or bounded Content-Length`)
    }
    const text = await response.text()
    const actualBytes = UTF8_ENCODER.encode(text).byteLength
    if (actualBytes > maximumBytes) {
      throw new Error(`${label} exceeds the ${maximumBytes}-byte safety limit`)
    }
    await reportProgress?.({ stage: 'parsing' })
    return JSON.parse(text)
  }
  // Fetch exposes a decoded body while Content-Length may describe a compressed
  // transfer representation, so it is an upper-bound precheck rather than an
  // exact decoded-size declaration.
  const encoding = response.headers.get('content-encoding')
  const totalBytes = !encoding || encoding === 'identity' ? declaredLength : null
  const text = await readTextStreamBounded(response.body, maximumBytes, null, label,
    reportProgress && (bytesRead => reportProgress({ stage: 'reading', bytesRead, totalBytes })),
  )
  await reportProgress?.({ stage: 'parsing' })
  return JSON.parse(text)
}

export async function decodeEmbeddedManifest(
  documentRoot: Document = document,
  reportProgress?: ReportLoadReporter,
): Promise<unknown | null> {
  const element = documentRoot.getElementById(INLINE_MANIFEST_ELEMENT_ID)
  if (!element) return null
  if (element.getAttribute('data-encoding') !== 'gzip+base64') {
    throw new Error('Embedded manifest has an unsupported encoding')
  }
  const rawSize = Number(element.getAttribute('data-uncompressed-bytes'))
  const compressedSize = Number(element.getAttribute('data-compressed-bytes'))
  if (
    !Number.isSafeInteger(rawSize) || rawSize < 0 || rawSize > MAX_MANIFEST_DOCUMENT_BYTES ||
    !Number.isSafeInteger(compressedSize) || compressedSize < 0 ||
    compressedSize > MAX_COMPRESSED_MANIFEST_BYTES
  ) {
    throw new Error('Embedded manifest has invalid or oversized declarations')
  }

  await reportProgress?.({ stage: 'decoding', bytesRead: 0, totalBytes: compressedSize })
  const encoded = element.textContent ?? ''
  const expectedEncodedCharacters = 4 * Math.ceil(compressedSize / 3)
  if (encoded.length !== expectedEncodedCharacters || /\s/u.test(encoded)) {
    throw new Error('Embedded manifest base64 size does not match its declaration')
  }
  const parts: Uint8Array<ArrayBuffer>[] = []
  let decodedBytes = 0
  for (let offset = 0; offset < encoded.length; offset += 32_768) {
    const binary = atob(encoded.slice(offset, offset + 32_768))
    const bytes = new Uint8Array(new ArrayBuffer(binary.length))
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index)
    }
    decodedBytes += bytes.byteLength
    if (decodedBytes > compressedSize) {
      throw new Error('Embedded manifest compressed data exceeds its declaration')
    }
    parts.push(bytes)
    await reportProgress?.({ stage: 'decoding', bytesRead: decodedBytes, totalBytes: compressedSize })
  }
  if (decodedBytes !== compressedSize) {
    throw new Error('Embedded manifest compressed size does not match its declaration')
  }
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This browser cannot decompress the offline manifest fallback')
  }
  const compressedStream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const part of parts) controller.enqueue(part)
      controller.close()
    },
  })
  // TypeScript's DOM declarations model DecompressionStream.writable as
  // BufferSource while ReadableStream.pipeThrough requires an invariant input
  // type. Uint8Array is the concrete BufferSource emitted above.
  const decompressor = new DecompressionStream('gzip') as unknown as {
    readable: ReadableStream<Uint8Array<ArrayBuffer>>
    writable: WritableStream<Uint8Array<ArrayBuffer>>
  }
  const decompressedStream = compressedStream.pipeThrough(decompressor)
  await reportProgress?.({ stage: 'decompressing', bytesRead: 0, totalBytes: rawSize })
  const text = await readTextStreamBounded(
    decompressedStream as ReadableStream<Uint8Array>,
    MAX_MANIFEST_DOCUMENT_BYTES,
    rawSize,
    'Embedded manifest',
    reportProgress && (bytesRead => reportProgress({ stage: 'decompressing', bytesRead, totalBytes: rawSize })),
  )
  await reportProgress?.({ stage: 'parsing' })
  return JSON.parse(text)
}

function validateTimingReference(
  reference: TimingReference,
  dutId: string,
  collectorId: string,
): TimingReference {
  if (
    !isObject(reference) || reference.schema_version !== '2.0' ||
    reference.scope !== 'dut' || typeof reference.source !== 'string' ||
    typeof reference.collector_id !== 'string' ||
    !Number.isSafeInteger(reference.size_bytes) || reference.size_bytes < 0 ||
    reference.size_bytes > MAX_TIMING_DOCUMENT_BYTES ||
    typeof reference.sha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(reference.sha256) ||
    typeof reference.snapshot_generation !== 'string' ||
    !/^[0-9a-f]{32}$/u.test(reference.snapshot_generation)
  ) {
    throw new Error('Collector timing reference is malformed')
  }
  if (reference.collector_id.toUpperCase() !== collectorId.toUpperCase()) {
    throw new Error('Collector timing reference targets a different collector')
  }
  const segments = reference.source.split('/')
  if (
    segments.length !== 3 || segments[0] !== dutId ||
    !['.metadata', 'metadata'].includes(segments[1]) || segments[2] !== 'timing.json' ||
    !segments[0] || segments[0] === '.' || segments[0] === '..' ||
    segments[0].includes('\\') || [...segments[0]].some(character => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint <= 31 || codePoint === 127
    })
  ) {
    throw new Error('Collector timing reference has an unsafe source path')
  }
  return reference
}

async function responseBytesBounded(
  response: Response,
  maximumBytes: number,
  label: string,
): Promise<Uint8Array> {
  if (!response.ok) {
    try { await response.body?.cancel() } catch { /* preserve request failure */ }
    throw new Error(`${label} request failed with HTTP ${response.status}`)
  }
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const declared = Number(contentLength)
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maximumBytes) {
      try { await response.body?.cancel() } catch { /* preserve bound failure */ }
      throw new Error(`${label} has an invalid or oversized Content-Length`)
    }
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer())
    if (bytes.byteLength > maximumBytes) throw new Error(`${label} exceeds its safety limit`)
    return bytes
  }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBytes) throw new Error(`${label} exceeds its safety limit`)
      chunks.push(value)
    }
  } catch (error) {
    try { await reader.cancel(error) } catch { /* retain original error */ }
    throw error
  } finally {
    reader.releaseLock()
  }
  const result = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.byteLength
  }
  return result
}

async function sha256BytesHex(bytes: Uint8Array): Promise<string> {
  // crypto.subtle exists only in secure contexts (https, localhost, file).
  // Reports are often served over plain http, so fall back to the pure-JS
  // digest there instead of throwing; document sizes are bounded by
  // MAX_TIMING_DOCUMENT_BYTES.
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return sha256BytesHexSync(bytes)
  const digestInput = new Uint8Array(bytes.byteLength)
  digestInput.set(bytes)
  const digest = await subtle.digest('SHA-256', digestInput.buffer)
  return [...new Uint8Array(digest)]
    .map(value => value.toString(16).padStart(2, '0'))
    .join('')
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' || typeof value === 'number'
    ? String(value)
    : fallback
}

function asNullableString(value: unknown): string | null {
  const normalized = asString(value).trim()
  return normalized || null
}

function asStringList(value: unknown): string[] {
  const values = Array.isArray(value) ? value : typeof value === 'string' ? [value] : []
  return [...new Set(values.map(asNullableString).filter((entry): entry is string => entry !== null))]
}

function normalizeFileIndex(value: unknown): FileEntry[] {
  if (!Array.isArray(value)) return []
  return value.filter(
    (entry): entry is FileEntry => isObject(entry) && typeof entry.path === 'string',
  )
}

function asNonNegativeNumber(value: unknown): number {
  const normalized = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(normalized) && normalized >= 0 ? normalized : 0
}

function asNullableInteger(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null
  const normalized = typeof value === 'number' ? value : Number(value)
  return Number.isInteger(normalized) && normalized >= 0 ? normalized : null
}

const RUN_COUNT_FIELDS: Array<keyof CanonicalCollectorCounts> = [
  'total_collectors', 'pending_collectors', 'running_collectors',
  'completed_collectors', 'degraded_collectors', 'partial_collectors', 'failed_collectors',
  'skipped_collectors', 'cancelled_collectors', 'baseboard_excluded',
  'capability_excluded', 'config_excluded',
]
const LEGACY_RUN_COUNT_FIELDS = RUN_COUNT_FIELDS.filter(
  field => field !== 'degraded_collectors',
)

const RUN_RESULT_FIELDS = [
  'schema_version', 'mode', 'runtime_status', 'collection_status',
  'collector_counts', 'terminal_snapshot_committed',
  'explicit_domain_failure', 'dut_roster', 'affected_duts', 'reasons',
] as const
const EXIT_CODE_RUN_RESULT_FIELDS = [...RUN_RESULT_FIELDS, 'exit_code'] as const
const IDENTITY_RUN_RESULT_FIELDS = [...RUN_RESULT_FIELDS, 'run_identity'] as const
const EXIT_CODE_IDENTITY_RUN_RESULT_FIELDS = [
  ...RUN_RESULT_FIELDS, 'exit_code', 'run_identity',
] as const
const RUN_IDENTITY_FIELDS = [
  'schema_version', 'tool', 'catalog', 'effective_config_sha256',
  'invocation', 'output', 'identity_sha256',
] as const
const RUN_IDENTITY_TOOL_FIELDS = [
  'version', 'build_hash', 'source_mode', 'source_revision', 'build_timestamp_utc',
] as const
const RUN_IDENTITY_CATALOG_FIELDS = [
  'name', 'version', 'sha256', 'size_bytes', 'binding',
] as const
const RUN_IDENTITY_INVOCATION_FIELDS = [
  'resolved_level', 'resolved_profile', 'resolved_plan_sha256', 'invocation_sha256',
] as const
const RUN_IDENTITY_OUTPUT_FIELDS = [
  'mode', 'caller_relation', 'caller_path', 'resolved_path', 'generated_path',
] as const
const RUN_PATH_IDENTITY_FIELDS = [
  'path_sha256', 'version_alignment', 'level_alignment', 'profile_alignment',
] as const
const MAX_CATALOG_SNAPSHOT_BYTES = 50 * 1024 * 1024
export const MAX_MANIFEST_DOCUMENT_BYTES = 128 * 1024 * 1024
const MAX_COMPRESSED_MANIFEST_BYTES = 64 * 1024 * 1024
const MAX_TIMING_DOCUMENT_BYTES = 16 * 1024 * 1024
const INLINE_MANIFEST_ELEMENT_ID = '__NVDEBUG_MANIFEST_GZIP__'
const MAX_TRACKED_COLLECTOR_RECORDS = 100_000
const MAX_DUTS = 500
const MAX_DUT_ID_BYTES = 255
const MAX_RESULT_REASONS = 32
const MAX_RESULT_REASON_CHARACTERS = 512
const MAX_RESULT_REASON_BYTES = 2048
const MAX_RAW_RESULT_REASON_CHARACTERS = MAX_RESULT_REASON_BYTES * 4
const UTF8_ENCODER = new TextEncoder()
const MAX_TIMING_CACHE_ENTRIES = 8
const MAX_TIMING_CACHE_BYTES = 32 * 1024 * 1024
const MAX_TIMING_IN_FLIGHT = 4
const COLLECTOR_FAILURE_CATEGORIES = new Set<CollectorFailureCategory>([
  'timeout',
  'dependency-missing',
  'auth-failure',
  'transport-failure',
  'parser-failure',
  'data-quality',
  'internal-error',
])
const OUTCOME_CONDITION_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u
const OUTCOME_ATTRIBUTE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u
const MAX_OUTCOME_MESSAGES = 32
const MAX_OUTCOME_ATTRIBUTES = 32
const MAX_OUTCOME_ATTRIBUTE_ITEMS = 32
const MAX_TIMING_COLLECTORS = 100_000
const MAX_TIMING_OPERATIONS = 100_000
const MAX_TIMING_ARTIFACTS = 100_000
const MAX_TIMING_ARTIFACT_PATHS_PER_OPERATION = 32
const MAX_TIMING_TEXT_BYTES = 4_096
const timingDocumentCache = new Map<
  string,
  { document: Record<string, any>, sizeBytes: number }
>()
const timingDocumentInflight = new Map<string, Promise<Record<string, any>>>()
let timingDocumentCacheBytes = 0
let timingDocumentCacheGeneration = 0

function cacheTimingDocument(
  source: string,
  document: Record<string, any>,
  sizeBytes: number,
): void {
  const previous = timingDocumentCache.get(source)
  if (previous) {
    timingDocumentCacheBytes -= previous.sizeBytes
    timingDocumentCache.delete(source)
  }
  while (
    timingDocumentCache.size > 0 &&
    (timingDocumentCache.size >= MAX_TIMING_CACHE_ENTRIES ||
      timingDocumentCacheBytes + sizeBytes > MAX_TIMING_CACHE_BYTES)
  ) {
    const oldest = timingDocumentCache.keys().next().value as string
    const evicted = timingDocumentCache.get(oldest)!
    timingDocumentCache.delete(oldest)
    timingDocumentCacheBytes -= evicted.sizeBytes
  }
  if (sizeBytes <= MAX_TIMING_CACHE_BYTES) {
    timingDocumentCache.set(source, { document, sizeBytes })
    timingDocumentCacheBytes += sizeBytes
  }
}

function clearTimingDocumentCache(): void {
  timingDocumentCache.clear()
  timingDocumentCacheBytes = 0
  timingDocumentCacheGeneration += 1
}

function timingDocumentCacheKey(reference: TimingReference): string {
  return [
    reference.source,
    String(reference.size_bytes),
    reference.sha256,
    reference.snapshot_generation,
  ].join('\u0000')
}

function isBoundedTimingText(value: unknown, nullable = false): boolean {
  return (
    (nullable && value === null) ||
    (typeof value === 'string' && UTF8_ENCODER.encode(value).byteLength <= MAX_TIMING_TEXT_BYTES)
  )
}

function isNullableNonNegativeNumber(value: unknown): boolean {
  return value === null || (
    typeof value === 'number' && Number.isFinite(value) && value >= 0
  )
}

function isNonNegativeNumber(value: unknown): boolean {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

function isNullableNonNegativeInteger(value: unknown): boolean {
  return value === null || (
    Number.isSafeInteger(value) && (value as number) >= 0
  )
}

function validateGranularTimingShape(
  value: unknown,
  cardinality: { operations: number, artifacts: number, artifactPaths: number },
): value is GranularCollectorTiming {
  if (!isObject(value)) return false
  if (
    !isBoundedTimingText(value.collector_started_at) ||
    !isBoundedTimingText(value.collector_ended_at) ||
    !isNonNegativeNumber(value.wall_clock_duration_seconds) ||
    value.wall_clock_is_authoritative !== true ||
    !isNonNegativeNumber(value.cumulative_operation_time_seconds) ||
    value.operation_aggregation !== 'top_level_contributing_spans' ||
    !isNonNegativeNumber(value.nested_operation_time_excluded_seconds) ||
    !isNonNegativeNumber(value.active_operation_union_seconds) ||
    !isNonNegativeNumber(value.overlapped_operation_time_seconds) ||
    !isNonNegativeNumber(value.unattributed_wall_time_seconds) ||
    value.operation_sum_equals_wall_clock !== false
  ) return false
  const operations = value.operations
  const artifacts = value.artifact_timings
  if (!Array.isArray(operations) || !Array.isArray(artifacts)) return false
  cardinality.operations += operations.length
  cardinality.artifacts += artifacts.length
  if (
    cardinality.operations > MAX_TIMING_OPERATIONS ||
    cardinality.artifacts > MAX_TIMING_ARTIFACTS
  ) return false

  const operationIds = new Set<string>()
  for (const operation of operations) {
    const metadata = isObject(operation) && isObject(operation.metadata)
      ? operation.metadata
      : null
    if (
      !isObject(operation) ||
      !isBoundedTimingText(operation.operation_id) ||
      operationIds.has(operation.operation_id) ||
      !isBoundedTimingText(operation.parent_id, true) ||
      !isBoundedTimingText(operation.operation_type) ||
      !isBoundedTimingText(operation.name) ||
      !isBoundedTimingText(operation.stage, true) ||
      !isBoundedTimingText(operation.hook, true) ||
      !isBoundedTimingText(operation.started_at, true) ||
      !isBoundedTimingText(operation.ended_at, true) ||
      !isNullableNonNegativeNumber(operation.duration_seconds) ||
      !isBoundedTimingText(operation.status) ||
      typeof operation.contributes_to_active_time !== 'boolean' ||
      !isNullableNonNegativeInteger(operation.size_bytes) ||
      metadata === null ||
      Object.keys(metadata).length > 16 ||
      Object.entries(metadata).some(([key, metadataValue]) => (
        UTF8_ENCODER.encode(key).byteLength > 128 ||
        !(
          metadataValue === null || typeof metadataValue === 'boolean' ||
          (typeof metadataValue === 'number' && Number.isFinite(metadataValue)) ||
          (typeof metadataValue === 'string' && UTF8_ENCODER.encode(metadataValue).byteLength <= 128) ||
          (
            isObject(metadataValue) &&
            Object.keys(metadataValue).every(field => ['type', 'item_count'].includes(field)) &&
            isBoundedTimingText(metadataValue.type) &&
            (
              metadataValue.item_count === undefined ||
              (Number.isSafeInteger(metadataValue.item_count) && metadataValue.item_count >= 0)
            )
          )
        )
      )) ||
      !Array.isArray(operation.artifact_paths) ||
      operation.artifact_paths.length > MAX_TIMING_ARTIFACT_PATHS_PER_OPERATION ||
      operation.artifact_paths.some(path => !isBoundedTimingText(path)) ||
      (operation.error !== undefined && !isBoundedTimingText(operation.error, true))
    ) return false
    operationIds.add(operation.operation_id)
    cardinality.artifactPaths += operation.artifact_paths.length
    if (cardinality.artifactPaths > MAX_TIMING_ARTIFACTS) return false
  }

  const qualities = new Set([
    'measured', 'measured_duration_only', 'estimated', 'unavailable',
  ])
  const scopes = new Set(['artifact', 'shared_operation', 'shared_requests', 'none'])
  for (const artifact of artifacts) {
    if (
      !isObject(artifact) ||
      !isBoundedTimingText(artifact.path) ||
      !isBoundedTimingText(artifact.operation_id, true) ||
      !isBoundedTimingText(artifact.measurement) ||
      !qualities.has(artifact.measurement_quality) ||
      !scopes.has(artifact.measurement_scope) ||
      !Number.isSafeInteger(artifact.shared_operation_artifact_count) ||
      artifact.shared_operation_artifact_count < 0 ||
      (
        artifact.shared_request_operation_count !== undefined &&
        (
          !Number.isSafeInteger(artifact.shared_request_operation_count) ||
          artifact.shared_request_operation_count < 1
        )
      ) ||
      !isBoundedTimingText(artifact.started_at, true) ||
      !isBoundedTimingText(artifact.ended_at, true) ||
      !isNullableNonNegativeNumber(artifact.duration_seconds) ||
      !isNullableNonNegativeInteger(artifact.size_bytes) ||
      !isBoundedTimingText(artifact.status)
    ) return false
  }
  return true
}

function validateTimingDocument(
  candidate: unknown,
  binding: TimingReference,
): Record<string, any> {
  if (!isObject(candidate) || !isObject(candidate.collectors)) {
    throw new Error('Detailed timing document is malformed')
  }
  if (candidate.snapshot_generation !== binding.snapshot_generation) {
    throw new Error('Detailed timing snapshot does not match its reference')
  }
  const entries = Object.entries(candidate.collectors)
  if (entries.length > MAX_TIMING_COLLECTORS) {
    throw new Error('Detailed timing collector cardinality exceeds its safety limit')
  }
  const normalizedIds = new Set<string>()
  const cardinality = { operations: 0, artifacts: 0, artifactPaths: 0 }
  for (const [collectorId, record] of entries) {
    const normalized = collectorId.toUpperCase()
    if (
      !isBoundedTimingText(collectorId) || !collectorId ||
      normalizedIds.has(normalized) || !isObject(record)
    ) {
      throw new Error('Detailed timing collector entry is malformed or ambiguous')
    }
    normalizedIds.add(normalized)
    const detailed = isObject(record.timing) ? record.timing : record
    const hasOperations = Object.prototype.hasOwnProperty.call(detailed, 'operations')
    const hasArtifacts = Object.prototype.hasOwnProperty.call(detailed, 'artifact_timings')
    if (
      (hasOperations || hasArtifacts) &&
      !validateGranularTimingShape(detailed, cardinality)
    ) {
      throw new Error('Detailed timing operation or artifact entry is malformed')
    }
  }
  return candidate
}

async function fetchTimingDocument(
  binding: TimingReference,
  cacheKey: string,
): Promise<Record<string, any>> {
  const cached = timingDocumentCache.get(cacheKey)
  if (cached) {
    timingDocumentCache.delete(cacheKey)
    timingDocumentCache.set(cacheKey, cached)
    return cached.document
  }
  const cacheGeneration = timingDocumentCacheGeneration
  const inflightKey = `${cacheGeneration}\u0000${cacheKey}`
  const existing = timingDocumentInflight.get(inflightKey)
  if (existing) return existing
  if (timingDocumentInflight.size >= MAX_TIMING_IN_FLIGHT) {
    throw new Error(
      `Too many detailed timing documents are already loading; ` +
      `the ${MAX_TIMING_IN_FLIGHT + 1}th distinct request is rejected`,
    )
  }

  const pending = (async (): Promise<Record<string, any>> => {
    let rawBytes: Uint8Array
    if (typeof location !== 'undefined' && location.protocol === 'file:') {
      const fileSystemStore = useFileSystemStore()
      if (!fileSystemStore.directoryLoaded) {
        throw new Error('Select the collection folder to load detailed timing')
      }
      const timingFile = fileSystemStore.getFile(binding.source)
      if (!timingFile) {
        throw new Error(`Detailed timing file was not found: ${binding.source}`)
      }
      if (timingFile.size !== binding.size_bytes) {
        throw new Error('Detailed timing size does not match its reference')
      }
      rawBytes = new Uint8Array(await timingFile.arrayBuffer())
      if (rawBytes.byteLength > MAX_TIMING_DOCUMENT_BYTES) {
        throw new Error('Detailed timing exceeds its safety limit')
      }
    } else {
      const encodedSource = binding.source.split('/').map(encodeURIComponent).join('/')
      const response = await fetch(new URL(`../${encodedSource}`, window.location.href), {
        credentials: 'same-origin',
      })
      rawBytes = await responseBytesBounded(
        response,
        MAX_TIMING_DOCUMENT_BYTES,
        'Detailed timing',
      )
    }
    if (rawBytes.byteLength !== binding.size_bytes) {
      throw new Error('Detailed timing size does not match its reference')
    }
    if (await sha256BytesHex(rawBytes) !== binding.sha256) {
      throw new Error('Detailed timing digest does not match its reference')
    }
    const candidate: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(rawBytes),
    )
    const document = validateTimingDocument(candidate, binding)
    if (cacheGeneration === timingDocumentCacheGeneration) {
      cacheTimingDocument(cacheKey, document, rawBytes.byteLength)
    }
    return document
  })()
  timingDocumentInflight.set(inflightKey, pending)
  try {
    return await pending
  } finally {
    if (timingDocumentInflight.get(inflightKey) === pending) {
      timingDocumentInflight.delete(inflightKey)
    }
  }
}
const SUCCESS_ONLY_RUN_REASONS = new Set([
  'complete', 'completed', 'completed successfully', 'ok',
  'pass', 'passed', 'success', 'successful',
])
const SHA256_PATTERN = /^[0-9a-f]{64}$/u
const SOURCE_REVISION_PATTERN = /^[0-9a-f]{40}$/u
const SEMANTIC_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/u
const BUILD_HASH_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u
const BUILD_TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u
const CATALOG_NAME_PATTERN = /^Telemetry_Catalog_v([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.xlsx$/u
const ALIGNMENTS = new Set(['aligned', 'conflict', 'not_declared'])
const OUTPUT_MODES = new Set([
  'configured_generated', 'caller_based_generated', 'caller_supplied_append',
])
const CALLER_RELATIONS = new Set(['absent', 'same', 'descendant'])
const SOURCE_MODES = new Set(['frozen', 'source', 'unknown'])
const CATALOG_BINDINGS = new Set(['manifest_bound', 'operator_supplied', 'discovered'])
const RESOLVED_LEVELS = new Set(['L1', 'L2', 'L3', 'unknown'])
const RESOLVED_PROFILES = new Set(['custom', 'level', 'planning', 'streaming', 'unknown'])
const SHA256_ROUND_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

function hasOwn(value: Record<string, any>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, field)
}

function ownDataValue(value: Record<string, any>, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, field)
  if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) {
    invalidRunResult(`${field} is not a plain data field`)
  }
  return descriptor.value
}

function invalidRunResult(detail: string): never {
  throw new Error(`Invalid canonical run_result: ${detail}`)
}

function hasExactKeys(value: Record<string, any>, fields: readonly string[]): boolean {
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const keys = Reflect.ownKeys(value)
  if (
    keys.length !== fields.length ||
    keys.some(key => typeof key !== 'string' || !fields.includes(key))
  ) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return fields.every(field => {
    const descriptor = descriptors[field]
    return descriptor?.enumerable === true && 'value' in descriptor
  })
}

function isPlainDataArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return false
  }
  const keys = Reflect.ownKeys(value)
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return Array.from({ length: value.length }, (_, index) => String(index)).every(
    key => keys.includes(key) && descriptors[key]?.enumerable === true && 'value' in descriptors[key],
  )
}

function isPlainDataRecord(value: unknown): value is Record<string, unknown> {
  if (!isObject(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const keys = Reflect.ownKeys(value)
  if (keys.some(key => typeof key !== 'string')) return false
  const descriptors = Object.getOwnPropertyDescriptors(value)
  return (keys as string[]).every(key => {
    const descriptor = descriptors[key]
    return descriptor?.enumerable === true && 'value' in descriptor
  })
}

function plainDataEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!isPlainDataArray(left) || !isPlainDataArray(right) || left.length !== right.length) {
      return false
    }
    const leftDescriptors = Object.getOwnPropertyDescriptors(left)
    const rightDescriptors = Object.getOwnPropertyDescriptors(right)
    return Array.from({ length: left.length }, (_, index) => String(index)).every(
      key => plainDataEqual(leftDescriptors[key].value, rightDescriptors[key].value),
    )
  }
  if (!isPlainDataRecord(left) || !isPlainDataRecord(right)) return false
  const leftKeys = Object.keys(left)
  const rightKeys = Object.keys(right)
  if (
    leftKeys.length !== rightKeys.length ||
    leftKeys.some(key => !Object.prototype.hasOwnProperty.call(right, key))
  ) return false
  const leftDescriptors = Object.getOwnPropertyDescriptors(left)
  const rightDescriptors = Object.getOwnPropertyDescriptors(right)
  return leftKeys.every(
    key => plainDataEqual(leftDescriptors[key].value, rightDescriptors[key].value),
  )
}

function rotateRight(value: number, shift: number): number {
  return (value >>> shift) | (value << (32 - shift))
}

function sha256Hex(text: string): string {
  return sha256BytesHexSync(UTF8_ENCODER.encode(text))
}

function sha256BytesHexSync(input: Uint8Array): string {
  const bitLength = input.length * 8
  const paddedLength = Math.ceil((input.length + 1 + 8) / 64) * 64
  const bytes = new Uint8Array(paddedLength)
  bytes.set(input)
  bytes[input.length] = 0x80
  const view = new DataView(bytes.buffer)
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false)
  view.setUint32(paddedLength - 4, bitLength >>> 0, false)

  const state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])
  const schedule = new Uint32Array(64)
  for (let offset = 0; offset < bytes.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      schedule[index] = view.getUint32(offset + index * 4, false)
    }
    for (let index = 16; index < 64; index += 1) {
      const first = schedule[index - 15]
      const second = schedule[index - 2]
      const sigma0 = rotateRight(first, 7) ^ rotateRight(first, 18) ^ (first >>> 3)
      const sigma1 = rotateRight(second, 17) ^ rotateRight(second, 19) ^ (second >>> 10)
      schedule[index] = (
        schedule[index - 16] + sigma0 + schedule[index - 7] + sigma1
      ) >>> 0
    }

    let [a, b, c, d, e, f, g, h] = state
    for (let index = 0; index < 64; index += 1) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
      const choice = (e & f) ^ (~e & g)
      const temporary1 = (h + sum1 + choice + SHA256_ROUND_CONSTANTS[index] + schedule[index]) >>> 0
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
      const majority = (a & b) ^ (a & c) ^ (b & c)
      const temporary2 = (sum0 + majority) >>> 0
      h = g
      g = f
      f = e
      e = (d + temporary1) >>> 0
      d = c
      c = b
      b = a
      a = (temporary1 + temporary2) >>> 0
    }
    state[0] = (state[0] + a) >>> 0
    state[1] = (state[1] + b) >>> 0
    state[2] = (state[2] + c) >>> 0
    state[3] = (state[3] + d) >>> 0
    state[4] = (state[4] + e) >>> 0
    state[5] = (state[5] + f) >>> 0
    state[6] = (state[6] + g) >>> 0
    state[7] = (state[7] + h) >>> 0
  }
  return Array.from(state, word => word.toString(16).padStart(8, '0')).join('')
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value)
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return String(value)
  }
  if (!isPlainDataRecord(value)) {
    invalidRunResult('run_identity contains noncanonical data')
  }
  return `{${Object.keys(value).sort().map(
    key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
  ).join(',')}}`
}

function normalizeRunPathIdentity(value: unknown): RunPathIdentity {
  if (!isObject(value) || !hasExactKeys(value, RUN_PATH_IDENTITY_FIELDS)) {
    invalidRunResult('run_identity path fields are not exact')
  }
  const digest = value.path_sha256
  const alignments = [
    value.version_alignment,
    value.level_alignment,
    value.profile_alignment,
  ]
  if (
    (digest !== null && (typeof digest !== 'string' || !SHA256_PATTERN.test(digest))) ||
    alignments.some(alignment => typeof alignment !== 'string' || !ALIGNMENTS.has(alignment)) ||
    (digest === null && alignments.some(alignment => alignment !== 'not_declared'))
  ) {
    invalidRunResult('run_identity path facts are invalid')
  }
  return {
    path_sha256: digest as string | null,
    version_alignment: value.version_alignment as RunPathIdentity['version_alignment'],
    level_alignment: value.level_alignment as RunPathIdentity['level_alignment'],
    profile_alignment: value.profile_alignment as RunPathIdentity['profile_alignment'],
  }
}

function normalizeRunIdentity(value: unknown): RunIdentity {
  if (!isObject(value) || !hasExactKeys(value, RUN_IDENTITY_FIELDS)) {
    invalidRunResult('run_identity fields are not exact')
  }
  if (value.schema_version !== '1.1') {
    invalidRunResult('run_identity schema is unsupported')
  }
  const tool = value.tool
  const catalog = value.catalog
  const invocation = value.invocation
  const output = value.output
  if (!isObject(tool) || !hasExactKeys(tool, RUN_IDENTITY_TOOL_FIELDS)) {
    invalidRunResult('run_identity tool facts are malformed')
  }
  if (!isObject(catalog) || !hasExactKeys(catalog, RUN_IDENTITY_CATALOG_FIELDS)) {
    invalidRunResult('run_identity catalog facts are malformed')
  }
  if (!isObject(invocation) || !hasExactKeys(invocation, RUN_IDENTITY_INVOCATION_FIELDS)) {
    invalidRunResult('run_identity invocation facts are malformed')
  }
  if (!isObject(output) || !hasExactKeys(output, RUN_IDENTITY_OUTPUT_FIELDS)) {
    invalidRunResult('run_identity output facts are malformed')
  }

  const toolVersionValid =
    tool.version === 'unknown' || (
      typeof tool.version === 'string' &&
      UTF8_ENCODER.encode(tool.version).length <= 128 &&
      SEMANTIC_VERSION_PATTERN.test(tool.version)
    )
  const sourceRevisionValid =
    tool.source_revision === 'unknown' || (
      typeof tool.source_revision === 'string' &&
      SOURCE_REVISION_PATTERN.test(tool.source_revision)
    )
  const timestampValid =
    tool.build_timestamp_utc === 'unknown' || (
      typeof tool.build_timestamp_utc === 'string' &&
      BUILD_TIMESTAMP_PATTERN.test(tool.build_timestamp_utc) &&
      tool.build_timestamp_utc.slice(0, 4) !== '0000' &&
      !Number.isNaN(Date.parse(tool.build_timestamp_utc)) &&
      new Date(tool.build_timestamp_utc).toISOString().replace('.000Z', 'Z') === tool.build_timestamp_utc
    )
  if (
    !toolVersionValid ||
    typeof tool.build_hash !== 'string' || !BUILD_HASH_PATTERN.test(tool.build_hash) ||
    typeof tool.source_mode !== 'string' || !SOURCE_MODES.has(tool.source_mode) ||
    !sourceRevisionValid ||
    !timestampValid
  ) {
    invalidRunResult('run_identity tool facts are invalid')
  }

  const catalogMatch = (
    typeof catalog.name === 'string' &&
    UTF8_ENCODER.encode(catalog.name).length <= 128
  )
    ? CATALOG_NAME_PATTERN.exec(catalog.name)
    : null
  const catalogNameValid = catalog.name === 'unknown'
    ? catalog.version === 'unknown'
    : catalogMatch !== null && catalog.version === catalogMatch[1]
  if (
    !catalogNameValid ||
    typeof catalog.sha256 !== 'string' || !SHA256_PATTERN.test(catalog.sha256) ||
    !Number.isSafeInteger(catalog.size_bytes) || catalog.size_bytes <= 0 ||
    catalog.size_bytes > MAX_CATALOG_SNAPSHOT_BYTES ||
    typeof catalog.binding !== 'string' || !CATALOG_BINDINGS.has(catalog.binding) ||
    typeof value.effective_config_sha256 !== 'string' ||
    !SHA256_PATTERN.test(value.effective_config_sha256)
  ) {
    invalidRunResult('run_identity catalog or configuration facts are invalid')
  }
  if (
    typeof invocation.resolved_level !== 'string' ||
    !RESOLVED_LEVELS.has(invocation.resolved_level) ||
    typeof invocation.resolved_profile !== 'string' ||
    !RESOLVED_PROFILES.has(invocation.resolved_profile) ||
    typeof invocation.resolved_plan_sha256 !== 'string' ||
    !SHA256_PATTERN.test(invocation.resolved_plan_sha256) ||
    typeof invocation.invocation_sha256 !== 'string' ||
    !SHA256_PATTERN.test(invocation.invocation_sha256)
  ) {
    invalidRunResult('run_identity invocation facts are invalid')
  }
  if (
    typeof output.mode !== 'string' || !OUTPUT_MODES.has(output.mode) ||
    typeof output.caller_relation !== 'string' ||
    !CALLER_RELATIONS.has(output.caller_relation)
  ) {
    invalidRunResult('run_identity output mode or caller relation is invalid')
  }
  const callerPath = normalizeRunPathIdentity(output.caller_path)
  const resolvedPath = normalizeRunPathIdentity(output.resolved_path)
  const generatedPath = normalizeRunPathIdentity(output.generated_path)
  const callerDigest = callerPath.path_sha256
  const resolvedDigest = resolvedPath.path_sha256
  const generatedDigest = generatedPath.path_sha256
  const callerRelationValid = output.mode === 'configured_generated'
    ? output.caller_relation === 'absent' && callerDigest === null
    : output.mode === 'caller_based_generated'
      ? output.caller_relation === 'descendant' && callerDigest !== null && callerDigest !== resolvedDigest
      : (
          callerDigest !== null &&
          (output.caller_relation === 'same'
            ? callerDigest === resolvedDigest
            : output.caller_relation === 'descendant' && callerDigest !== resolvedDigest)
        )
  if (
    resolvedDigest === null ||
    !callerRelationValid ||
    (output.mode === 'caller_supplied_append'
      ? generatedDigest !== null
      : generatedDigest === null || generatedDigest !== resolvedDigest)
  ) {
    invalidRunResult('run_identity output paths contradict their mode')
  }

  const normalized: RunIdentity = {
    schema_version: '1.1',
    tool: {
      version: tool.version,
      build_hash: tool.build_hash,
      source_mode: tool.source_mode as RunIdentity['tool']['source_mode'],
      source_revision: tool.source_revision,
      build_timestamp_utc: tool.build_timestamp_utc,
    },
    catalog: {
      name: catalog.name,
      version: catalog.version,
      sha256: catalog.sha256,
      size_bytes: catalog.size_bytes,
      binding: catalog.binding as RunIdentity['catalog']['binding'],
    },
    effective_config_sha256: value.effective_config_sha256,
    invocation: {
      resolved_level: invocation.resolved_level as RunIdentity['invocation']['resolved_level'],
      resolved_profile: invocation.resolved_profile as RunIdentity['invocation']['resolved_profile'],
      resolved_plan_sha256: invocation.resolved_plan_sha256,
      invocation_sha256: invocation.invocation_sha256,
    },
    output: {
      mode: output.mode as RunIdentity['output']['mode'],
      caller_relation: output.caller_relation as RunIdentity['output']['caller_relation'],
      caller_path: callerPath,
      resolved_path: resolvedPath,
      generated_path: generatedPath,
    },
    identity_sha256: value.identity_sha256,
  }
  const invocationMaterial = {
    schema_version: normalized.schema_version,
    tool: normalized.tool,
    catalog: normalized.catalog,
    effective_config_sha256: normalized.effective_config_sha256,
    invocation: {
      resolved_level: normalized.invocation.resolved_level,
      resolved_profile: normalized.invocation.resolved_profile,
      resolved_plan_sha256: normalized.invocation.resolved_plan_sha256,
    },
    output: normalized.output,
  }
  const expectedInvocationDigest = sha256Hex(canonicalJson(invocationMaterial))
  if (normalized.invocation.invocation_sha256 !== expectedInvocationDigest) {
    invalidRunResult('run_identity invocation digest is inconsistent')
  }
  const identityMaterial = {
    ...invocationMaterial,
    invocation: normalized.invocation,
  }
  const expectedIdentityDigest = sha256Hex(canonicalJson(identityMaterial))
  if (
    typeof normalized.identity_sha256 !== 'string' ||
    !SHA256_PATTERN.test(normalized.identity_sha256) ||
    normalized.identity_sha256 !== expectedIdentityDigest
  ) {
    invalidRunResult('run_identity digest is inconsistent')
  }
  return normalized
}

function isBoundedIdentity(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    UTF8_ENCODER.encode(value).length <= MAX_DUT_ID_BYTES &&
    ![...value].some(character =>
      /\p{C}/u.test(character) || (character !== ' ' && /\p{Z}/u.test(character)),
    ) &&
    !['.', '..'].includes(value) &&
    !value.includes('/') &&
    !value.includes('\\')
  )
}

function isCanonicalReason(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    [...value].length <= MAX_RESULT_REASON_CHARACTERS &&
    UTF8_ENCODER.encode(value).length <= MAX_RESULT_REASON_BYTES &&
    value.split(/\s+/u).join(' ') === value &&
    ![...value].some(character =>
      /\p{C}/u.test(character) || (character !== ' ' && /\p{Z}/u.test(character)),
    )
  )
}

function isSuccessOnlyRunReason(value: string): boolean {
  return SUCCESS_ONLY_RUN_REASONS.has(
    value.split(/\s+/u).join(' ').replace(/^[ .!]+|[ .!]+$/gu, '').toLowerCase(),
  )
}

function normalizeIdentityList(value: unknown, field: string): string[] {
  if (
    !isPlainDataArray(value) ||
    value.length > MAX_DUTS ||
    value.some(item => !isBoundedIdentity(item)) ||
    new Set(value).size !== value.length
  ) {
    invalidRunResult(`${field} is not a bounded unique identity list`)
  }
  return [...value] as string[]
}

function expectedCollectionStatus(
  runtimeStatus: RunResult['runtime_status'],
  counts: CanonicalCollectorCounts,
  terminalSnapshotCommitted: boolean,
  explicitDomainFailure: boolean,
): RunResult['collection_status'] {
  if (!terminalSnapshotCommitted) {
    return runtimeStatus === 'interrupted' ? 'interrupted' : 'incomplete'
  }
  if (runtimeStatus === 'interrupted') return 'interrupted'
  if (counts.pending_collectors || counts.running_collectors) return 'incomplete'
  if (explicitDomainFailure) {
    return counts.completed_collectors || counts.degraded_collectors || counts.partial_collectors
      ? 'partial'
      : 'failed'
  }
  if (counts.failed_collectors || counts.cancelled_collectors) {
    return counts.completed_collectors || counts.degraded_collectors || counts.partial_collectors
      ? 'partial'
      : 'failed'
  }
  if (counts.degraded_collectors || counts.partial_collectors) return 'partial'
  if (counts.total_collectors && !counts.completed_collectors) return 'incomplete'
  return 'success'
}

function expectedRunResultExitCode(
  mode: RunResult['mode'],
  runtimeStatus: RunResult['runtime_status'],
  collectionStatus: RunResult['collection_status'],
): NonNullable<RunResult['exit_code']> {
  if (runtimeStatus === 'interrupted') return 130
  if (runtimeStatus === 'failed') return 1
  if (mode === 'planning') return 0
  if (collectionStatus === 'interrupted') return 130
  if (collectionStatus === 'partial' || collectionStatus === 'failed') return 3
  if (collectionStatus === 'incomplete') return 1
  return 0
}

function normalizeCanonicalCollectorCounts(value: unknown): CanonicalCollectorCounts {
  if (!isObject(value)) {
    invalidRunResult('collector counts are not exact bounded integers')
  }
  const current = hasExactKeys(value, RUN_COUNT_FIELDS)
  const legacy = hasExactKeys(value, LEGACY_RUN_COUNT_FIELDS)
  if (!current && !legacy) {
    invalidRunResult('collector counts are not exact bounded integers')
  }
  const normalized = Object.fromEntries(
    RUN_COUNT_FIELDS.map(field => [
      field,
      legacy && field === 'degraded_collectors' ? 0 : value[field],
    ]),
  ) as unknown as CanonicalCollectorCounts
  if (!RUN_COUNT_FIELDS.every(field => {
    const count = normalized[field]
    return (
      Number.isSafeInteger(count) &&
      count >= 0 &&
      count <= MAX_TRACKED_COLLECTOR_RECORDS
    )
  })) {
    invalidRunResult('collector counts are not exact bounded integers')
  }
  return normalized
}

function normalizeRunResult(value: unknown): RunResult | null {
  if (value === null) return null
  if (!isObject(value)) {
    invalidRunResult('document fields are not exact')
  }
  const hasExitCode = hasOwn(value, 'exit_code')
  const isLegacyResult = hasExactKeys(
    value,
    hasExitCode ? EXIT_CODE_RUN_RESULT_FIELDS : RUN_RESULT_FIELDS,
  )
  const isIdentityResult = hasExactKeys(
    value,
    hasExitCode ? EXIT_CODE_IDENTITY_RUN_RESULT_FIELDS : IDENTITY_RUN_RESULT_FIELDS,
  )
  if (!isLegacyResult && !isIdentityResult) {
    invalidRunResult('document fields are not exact')
  }
  if (
    (isLegacyResult && value.schema_version !== '1.0') ||
    (isIdentityResult && value.schema_version !== '1.1')
  ) {
    invalidRunResult('unsupported schema version')
  }
  const runIdentity = isIdentityResult
    ? normalizeRunIdentity(value.run_identity)
    : null
  const runtime = value.runtime_status
  const collection = value.collection_status
  const mode = value.mode
  if (!['success', 'failed', 'interrupted'].includes(runtime)) {
    invalidRunResult('runtime status is invalid')
  }
  if (!['success', 'partial', 'failed', 'interrupted', 'incomplete'].includes(collection)) {
    invalidRunResult('collection status is invalid')
  }
  if (!['collection', 'planning'].includes(mode) || !isObject(value.collector_counts)) {
    invalidRunResult('mode or collector counts are invalid')
  }
  if (
    runIdentity !== null &&
    ((mode === 'planning') !== (runIdentity.invocation.resolved_profile === 'planning'))
  ) {
    invalidRunResult('run_result mode and run_identity profile disagree')
  }
  if (
    typeof value.terminal_snapshot_committed !== 'boolean' ||
    typeof value.explicit_domain_failure !== 'boolean' ||
    !isPlainDataArray(value.reasons) ||
    value.reasons.length > MAX_RESULT_REASONS ||
    value.reasons.some(reason => !isCanonicalReason(reason))
  ) {
    invalidRunResult('snapshot flags or reasons are invalid')
  }
  const reasons = [...value.reasons] as string[]
  const dutRoster = normalizeIdentityList(value.dut_roster, 'dut_roster')
  const affectedDuts = normalizeIdentityList(value.affected_duts, 'affected_duts')
  if (!affectedDuts.every(dut => dutRoster.includes(dut))) {
    invalidRunResult('affected_duts is not a subset of dut_roster')
  }

  let collectorCounts: CanonicalCollectorCounts | Record<string, never>
  if (mode === 'collection') {
    collectorCounts = normalizeCanonicalCollectorCounts(value.collector_counts)
    const terminalCount =
      collectorCounts.pending_collectors +
      collectorCounts.running_collectors +
      collectorCounts.completed_collectors +
      collectorCounts.degraded_collectors +
      collectorCounts.partial_collectors +
      collectorCounts.failed_collectors +
      collectorCounts.skipped_collectors +
      collectorCounts.cancelled_collectors
    const excludedCount =
      collectorCounts.baseboard_excluded +
      collectorCounts.capability_excluded +
      collectorCounts.config_excluded
    if (
      collectorCounts.total_collectors !== terminalCount ||
      excludedCount > collectorCounts.skipped_collectors
    ) {
      invalidRunResult('collector counts are internally inconsistent')
    }
    if (collectorCounts.total_collectors > 0 && dutRoster.length === 0) {
      invalidRunResult('nonempty collection is missing its DUT roster')
    }
    if (!value.terminal_snapshot_committed && runtime === 'success') {
      invalidRunResult('uncommitted collection cannot report runtime success')
    }
    if (
      collection !== expectedCollectionStatus(
        runtime as RunResult['runtime_status'],
        collectorCounts,
        value.terminal_snapshot_committed,
        value.explicit_domain_failure,
      )
    ) {
      invalidRunResult('statuses contradict canonical collector counts')
    }
  } else {
    if (!hasExactKeys(value.collector_counts, [])) {
      invalidRunResult('planning result contains collector counts')
    }
    if (value.terminal_snapshot_committed || value.explicit_domain_failure) {
      invalidRunResult('planning result claims collection evidence')
    }
    const planningStatus = runtime === 'interrupted' ? 'interrupted' : 'incomplete'
    if (collection !== planningStatus) {
      invalidRunResult('planning result claims a collection outcome')
    }
    collectorCounts = {}
  }
  if (
    (runtime !== 'success' || collection !== 'success') &&
    (reasons.length === 0 || isSuccessOnlyRunReason(reasons[0]))
  ) {
    invalidRunResult('non-success result is missing a failure reason')
  }

  const exitCode = expectedRunResultExitCode(
    mode as RunResult['mode'],
    runtime as RunResult['runtime_status'],
    collection as RunResult['collection_status'],
  )
  if (
    hasExitCode &&
    (!Number.isSafeInteger(value.exit_code) || value.exit_code !== exitCode)
  ) {
    invalidRunResult('exit code contradicts canonical result state')
  }

  const result = {
    mode: mode as RunResult['mode'],
    runtime_status: runtime as RunResult['runtime_status'],
    collection_status: collection as RunResult['collection_status'],
    collector_counts: collectorCounts,
    terminal_snapshot_committed: value.terminal_snapshot_committed,
    explicit_domain_failure: value.explicit_domain_failure,
    dut_roster: dutRoster,
    affected_duts: affectedDuts,
    reasons,
    ...(hasExitCode ? { exit_code: exitCode } : {}),
  }
  return runIdentity === null
    ? { ...result, schema_version: '1.0' }
    : { ...result, schema_version: '1.1', run_identity: runIdentity }
}

function runResultsEqual(left: RunResult | null, right: RunResult | null): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

interface SelectionFailureProjection {
  failureType: string
  reason: string
  affectedDuts: string[]
  evidence: string
}

/**
 * Mirror the backend's bounded explicit-selection legacy projection.
 * A supported subtype and evidence path may refine severity only when its
 * reason and affected DUTs are already present in the canonical failure.
 */
function selectionFailureProjection(
  summary: Record<string, unknown>,
  result: RunResult,
): SelectionFailureProjection | null {
  const outcome = summary.run_outcome
  if (
    !result.explicit_domain_failure ||
    !isPlainDataRecord(outcome) ||
    outcome.status !== 'domain_failed' ||
    typeof outcome.failure_type !== 'string' ||
    !['explicit_selection_no_execution', 'explicit_selection_preflight_failure'].includes(
      outcome.failure_type,
    ) ||
    outcome.evidence !== '.metadata/selection_failure.json' ||
    typeof outcome.reason !== 'string' ||
    !outcome.reason.trim() ||
    !result.reasons.includes(outcome.reason) ||
    !Array.isArray(outcome.affected_duts) ||
    !outcome.affected_duts.length ||
    outcome.affected_duts.length > result.affected_duts.length ||
    !isPlainDataArray(outcome.affected_duts) ||
    !outcome.affected_duts.every(
      (dutId): dutId is string => typeof dutId === 'string' && result.affected_duts.includes(dutId),
    ) ||
    new Set(outcome.affected_duts).size !== outcome.affected_duts.length
  ) return null

  return {
    failureType: outcome.failure_type,
    reason: outcome.reason,
    affectedDuts: [...outcome.affected_duts],
    evidence: outcome.evidence,
  }
}

function canonicalOverallStatus(
  result: RunResult,
  selectionFailure: SelectionFailureProjection | null = null,
): NonNullable<CollectionSummary['overall_status']> {
  if (result.runtime_status === 'interrupted') return 'Interrupted'
  if (result.runtime_status === 'failed' || selectionFailure) return 'Failed'
  if (
    result.mode === 'collection' &&
    result.collector_counts.failed_collectors > 0
  ) return 'Failed'
  return {
    success: 'Passed',
    partial: 'Partial',
    failed: 'Failed',
    interrupted: 'Interrupted',
    incomplete: 'Incomplete',
  }[result.collection_status] as NonNullable<CollectionSummary['overall_status']>
}

function canonicalLegacyProjection(result: RunResult): {
  status: NonNullable<CollectionSummary['run_outcome_status']>
  failureType?: string
} {
  if (result.runtime_status === 'interrupted') return { status: 'interrupted' }
  if (result.runtime_status === 'failed') {
    return { status: 'runtime_failed', failureType: 'finalization_failure' }
  }
  if (result.collection_status === 'success') return { status: 'success' }
  if (result.collection_status === 'incomplete') {
    return { status: 'runtime_failed', failureType: 'incomplete_collection' }
  }
  if (result.collection_status === 'interrupted') return { status: 'interrupted' }
  return { status: 'domain_failed', failureType: 'collector_result_failure' }
}

function projectionsEqual(left: unknown, right: unknown): boolean {
  return plainDataEqual(left, right)
}

function validateSummaryProjection(
  rawSummary: Record<string, any>,
  result: RunResult | null,
): void {
  if (!isPlainDataRecord(rawSummary)) {
    invalidRunResult('collection_summary is not a plain data object')
  }
  let projectedCollectorCounts = rawSummary.collector_counts
  if (result?.mode === 'collection' && hasOwn(rawSummary, 'collector_counts')) {
    try {
      projectedCollectorCounts = normalizeCanonicalCollectorCounts(
        rawSummary.collector_counts,
      )
    } catch {
      invalidRunResult('collection_summary.collector_counts contradicts canonical truth')
    }
  }
  const duplicatedFields: Array<[string, unknown]> = [
    ['runtime_status', result?.runtime_status ?? null],
    ['collection_status', result?.collection_status ?? null],
    ['collector_counts', result?.collector_counts ?? null],
  ]
  for (const [field, expected] of duplicatedFields) {
    const actual = field === 'collector_counts'
      ? projectedCollectorCounts
      : rawSummary[field]
    if (hasOwn(rawSummary, field) && !projectionsEqual(actual, expected)) {
      invalidRunResult(`collection_summary.${field} contradicts canonical truth`)
    }
  }
  if (result === null) return

  const selectionFailure = selectionFailureProjection(rawSummary, result)
  const expectedOverall = canonicalOverallStatus(result, selectionFailure)
  if (hasOwn(rawSummary, 'overall_status') && rawSummary.overall_status !== expectedOverall) {
    invalidRunResult('collection_summary.overall_status contradicts canonical truth')
  }
  const legacy = selectionFailure
    ? { status: 'domain_failed' as const, failureType: selectionFailure.failureType }
    : canonicalLegacyProjection(result)
  const expectedReason = selectionFailure?.reason ?? result.reasons[0] ?? ''
  const expectedAffectedDuts = selectionFailure?.affectedDuts ?? result.affected_duts
  const hasDomainFailure = legacy.status === 'domain_failed'
  for (const [field, expected] of [
    ['domain_failure_type', hasDomainFailure ? legacy.failureType : undefined],
    ['domain_failure_reason', hasDomainFailure ? expectedReason : undefined],
    ['domain_failure_evidence', selectionFailure?.evidence],
  ] as const) {
    if (hasOwn(rawSummary, field) && rawSummary[field] !== expected) {
      invalidRunResult(`summary ${field} contradicts canonical truth`)
    }
  }
  if (
    hasOwn(rawSummary, 'run_outcome_status') &&
    rawSummary.run_outcome_status !== legacy.status
  ) {
    invalidRunResult('legacy outcome status contradicts canonical truth')
  }
  if (
    hasOwn(rawSummary, 'run_outcome_failure_type') &&
    rawSummary.run_outcome_failure_type !== legacy.failureType
  ) {
    invalidRunResult('legacy failure type contradicts canonical truth')
  }
  if (
    hasOwn(rawSummary, 'run_outcome_reason') &&
    rawSummary.run_outcome_reason !== expectedReason
  ) {
    invalidRunResult('legacy outcome reason contradicts canonical truth')
  }
  if (
    hasOwn(rawSummary, 'domain_failure') &&
    rawSummary.domain_failure !== (legacy.status === 'domain_failed')
  ) {
    invalidRunResult('legacy domain-failure flag contradicts canonical truth')
  }
  if (
    hasOwn(rawSummary, 'underlying_outcome') &&
    rawSummary.underlying_outcome != null
  ) {
    invalidRunResult('recursive legacy outcome is not authoritative')
  }
  if (hasOwn(rawSummary, 'run_outcome')) {
    const outcome = rawSummary.run_outcome
    if (
      !isPlainDataRecord(outcome) ||
      outcome.status !== legacy.status ||
      (hasOwn(outcome, 'adapter_schema_version') && outcome.adapter_schema_version !== '1.0') ||
      (hasOwn(outcome, 'canonical_runtime_status') && outcome.canonical_runtime_status !== result.runtime_status) ||
      (hasOwn(outcome, 'canonical_collection_status') && outcome.canonical_collection_status !== result.collection_status) ||
      (hasOwn(outcome, 'reason') && outcome.reason !== expectedReason) ||
      (hasOwn(outcome, 'affected_duts') && !projectionsEqual(outcome.affected_duts, expectedAffectedDuts)) ||
      (hasOwn(outcome, 'failure_type') && outcome.failure_type !== legacy.failureType) ||
      (selectionFailure
        ? outcome.evidence !== selectionFailure.evidence
        : hasOwn(outcome, 'evidence')) ||
      hasOwn(outcome, 'underlying_outcome')
    ) {
      invalidRunResult('legacy run_outcome contradicts canonical truth')
    }
  }
}

function asMetadataSources(value: unknown): Record<string, string | null> {
  if (!isObject(value)) return {}
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, source]) => source === null || typeof source === 'string')
      .map(([key, source]) => [key, source === null ? null : source.trim() || null]),
  )
}

function configuredAnalyzerUrl(): string | null {
  const configured = import.meta.env.VITE_OPENBMC_COREDUMP_ANALYZER_URL?.trim()
  if (!configured) return null

  try {
    const parsed = new URL(configured)
    if (
      !['http:', 'https:'].includes(parsed.protocol) ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password
    ) {
      return null
    }
    return parsed.href
  } catch {
    return null
  }
}

function safeAnalyzerUrl(_value: unknown): string | null {
  // A collection manifest is untrusted input. Only a destination embedded by
  // the report deployment may become a clickable core-upload target.
  return configuredAnalyzerUrl()
}

function normalizeCoreDumpRecord(
  value: unknown,
  analyzerUrl: string | null,
): OpenBMCCoreDumpRecord {
  const raw = isObject(value) ? value : {}
  const collector = isObject(raw.collector) ? raw.collector : {}
  const handoff = isObject(raw.handoff) ? raw.handoff : {}
  const artifactPath = asString(
    raw.artifact_path ?? raw.core_path ?? raw.path,
  ).replace(/\\/g, '/')
  const pathParts = artifactPath.split('/').filter(Boolean)
  const filename =
    asString(raw.filename) || pathParts[pathParts.length - 1] || ''
  const openbmcCommit = asNullableString(raw.openbmc_commit ?? raw.commit)
  const machine = asNullableString(raw.machine)
  const validation = asString(raw.validation, 'unverified')

  const suppliedMissing = asStringList(
    raw.missing_required_metadata ?? raw.missing_metadata,
  )
  const missingRequired = [
    ...new Set([
      ...suppliedMissing,
      ...[
        !artifactPath ? 'artifact_path' : null,
        !openbmcCommit ? 'openbmc_commit' : null,
        !machine ? 'machine' : null,
        validation !== 'validated_raw_elf_core'
          ? 'valid_core_dump'
          : null,
      ].filter((entry): entry is string => entry !== null),
    ]),
  ]
  const preparationRequired =
    raw.preparation_required === true
      ? ['Manual preparation is required before upload.']
      : asStringList(raw.preparation_required)
  const readyForAnalyzer =
    missingRequired.length === 0 &&
    preparationRequired.length === 0 &&
    validation === 'validated_raw_elf_core' &&
    (typeof raw.ready_for_analyzer === 'boolean'
      ? raw.ready_for_analyzer
      : true)

  return {
    artifact_path: artifactPath,
    archive_member_path: asNullableString(raw.archive_member_path),
    filename,
    size_bytes: asNonNegativeNumber(raw.size_bytes ?? raw.size),
    outer_archive_size_bytes:
      raw.outer_archive_size_bytes === null ||
      raw.outer_archive_size_bytes === undefined
        ? null
        : asNonNegativeNumber(raw.outer_archive_size_bytes),
    source_dut: asString(raw.source_dut ?? raw.dut_id, 'unknown'),
    collector: {
      id: asString(collector.id ?? raw.collector_id),
      name: asString(collector.name ?? raw.collector_name),
      group: asString(collector.group ?? raw.collector_group),
      path: asString(collector.path),
    },
    openbmc_commit: openbmcCommit,
    machine,
    baseboard: asNullableString(raw.baseboard),
    service: asNullableString(raw.service),
    pid: asNullableInteger(raw.pid),
    timestamp: asNullableString(raw.timestamp),
    compression: asString(raw.compression, 'unknown'),
    validation,
    metadata_sources: asMetadataSources(raw.metadata_sources),
    ready_for_analyzer: readyForAnalyzer,
    missing_required_metadata: missingRequired,
    warnings: asStringList(raw.warnings),
    preparation_required: preparationRequired,
    handoff: {
      action: 'manual_upload',
      analyzer_url: safeAnalyzerUrl(handoff.analyzer_url ?? analyzerUrl),
      upload_performed: false,
    },
  }
}

function normalizeOpenBMCCoreDumps(
  value: unknown,
  manifestGeneratedAt: string,
): OpenBMCCoreDumpManifest {
  const raw = isObject(value) ? value : {}
  const analyzer = isObject(raw.analyzer) ? raw.analyzer : {}
  const privacy = isObject(raw.privacy) ? raw.privacy : {}
  const analyzerUrl = safeAnalyzerUrl(analyzer.url)
  const coreDumps = Array.isArray(raw.core_dumps)
    ? raw.core_dumps
        .filter(isObject)
        .map(entry => normalizeCoreDumpRecord(entry, analyzerUrl))
    : []
  const analyzerReadyCount = coreDumps.filter(core => core.ready_for_analyzer).length
  const archiveScan = isObject(raw.archive_scan) ? raw.archive_scan : {}
  const uninspectedArchives = Array.isArray(archiveScan.uninspected_archives)
    ? archiveScan.uninspected_archives.filter(isObject).map(entry => ({
        artifact_path: asString(entry.artifact_path).replace(/\\/g, '/'),
        size_bytes: asNonNegativeNumber(entry.size_bytes),
        status: asString(entry.status, 'unknown'),
        reason: asString(entry.reason, 'not recorded'),
      }))
    : []
  const omittedArchiveDetails = asNonNegativeNumber(
    archiveScan.uninspected_archive_details_omitted,
  )
  const uninspectedArchiveCount = Math.max(
    asNonNegativeNumber(
      archiveScan.uninspected_archive_count ??
        uninspectedArchives.length,
    ),
    uninspectedArchives.length + omittedArchiveDetails,
  )

  return {
    schema_version: asString(raw.schema_version, '1.0'),
    generated_at: asString(raw.generated_at, manifestGeneratedAt),
    analyzer: {
      name: asString(analyzer.name, 'OpenBMC Core Dump Analyzer'),
      url: analyzerUrl,
      integration_mode: 'manual_handoff',
      automatic_upload: false,
    },
    privacy: {
      classification: asString(
        privacy.classification,
        'sensitive_diagnostic_artifact',
      ),
      notice: asString(privacy.notice, DEFAULT_PRIVACY_NOTICE),
    },
    summary: {
      core_dump_count: coreDumps.length,
      analyzer_ready_count: analyzerReadyCount,
      needs_metadata_count: coreDumps.length - analyzerReadyCount,
    },
    scan_warnings: asStringList(raw.scan_warnings),
    archive_scan: {
      complete:
        uninspectedArchiveCount > 0
          ? false
          : typeof archiveScan.complete === 'boolean'
          ? archiveScan.complete
          : true,
      archives_inspected: asNonNegativeNumber(
        archiveScan.archives_inspected,
      ),
      compressed_bytes_inspected: asNonNegativeNumber(
        archiveScan.compressed_bytes_inspected,
      ),
      decompressed_bytes_consumed: asNonNegativeNumber(
        archiveScan.decompressed_bytes_consumed,
      ),
      members_inspected: asNonNegativeNumber(
        archiveScan.members_inspected,
      ),
      uninspected_archive_count: uninspectedArchiveCount,
      uninspected_archive_details_omitted: omittedArchiveDetails,
      uninspected_archives: uninspectedArchives,
    },
    core_dumps: coreDumps,
  }
}

function scrubDiagnosticSecrets(value: string): string {
  return value
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/giu, '$1XXXX@')
    .replace(
      /([?&](?:access[_-]?token|api[_-]?key|auth|credential|password|secret|signature|x-amz-credential|x-amz-signature)=)[^&#\s]*/giu,
      '$1XXXX',
    )
    .replace(
      /\b(password|passwd|token|secret|credential|api[_-]?key)(\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/giu,
      '$1$2XXXX',
    )
    .replace(/\b(bearer|token)\s+[^\s}\]\r\n]+/giu, '$1 XXXX')
    .replace(
      /(^|\s)(authorization\s*:\s*)(?:basic|bearer)?\s*[^\s,;]+/gimu,
      '$1$2XXXX',
    )
    .replace(
      /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/gu,
      'XXXX',
    )
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu, 'XXXX')
}

function boundedCollectorReason(value: unknown): string {
  const canonical = scrubDiagnosticSecrets(asString(value))
    .replace(/[\p{C}\p{Z}]+/gu, ' ')
    .split(/\s+/u)
    .filter(Boolean)
    .join(' ')
  const characters = [...canonical].slice(0, MAX_RESULT_REASON_CHARACTERS)
  const bounded: string[] = []
  let byteCount = 0
  for (const character of characters) {
    const encodedBytes = UTF8_ENCODER.encode(character).byteLength
    if (byteCount + encodedBytes > MAX_RESULT_REASON_BYTES) break
    bounded.push(character)
    byteCount += encodedBytes
  }
  return bounded.join('')
}

function normalizeOutcomeAttribute(value: unknown): CollectorOutcomeAttribute | undefined {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return typeof value === 'string' ? boundedCollectorReason(value) : value
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined
  if (!Array.isArray(value) || value.length > MAX_OUTCOME_ATTRIBUTE_ITEMS) return undefined
  const projected: Array<string | number | boolean | null> = []
  for (const item of value) {
    const normalized = normalizeOutcomeAttribute(item)
    if (normalized === undefined || Array.isArray(normalized)) return undefined
    projected.push(normalized)
  }
  return projected
}

function normalizeCollectorOutcomeDetails(value: unknown): CollectorOutcomeDetails | undefined {
  if (
    !isObject(value) ||
    value.schema_version !== '1.0' ||
    !COLLECTOR_FAILURE_CATEGORIES.has(value.category) ||
    typeof value.condition !== 'string' ||
    !OUTCOME_CONDITION_PATTERN.test(value.condition) ||
    !Array.isArray(value.messages) ||
    value.messages.length < 1 ||
    value.messages.length > MAX_OUTCOME_MESSAGES ||
    !value.messages.every(message => typeof message === 'string') ||
    !isObject(value.attributes) ||
    Object.keys(value.attributes).length > MAX_OUTCOME_ATTRIBUTES
  ) return undefined

  const attributes: Record<string, CollectorOutcomeAttribute> = {}
  for (const [key, rawAttribute] of Object.entries(value.attributes)) {
    if (!OUTCOME_ATTRIBUTE_PATTERN.test(key)) continue
    const attribute = normalizeOutcomeAttribute(rawAttribute)
    if (attribute !== undefined) attributes[key] = attribute
  }
  const messages = value.messages.map(message => boundedCollectorReason(message))
  if (messages.some(message => message.length === 0)) return undefined
  return {
    schema_version: '1.0',
    category: value.category as CollectorFailureCategory,
    condition: value.condition,
    messages,
    attributes,
  }
}

function normalizeErrors(value: unknown): ErrorEntry[] {
  return normalizeErrorEntries(value, MAX_RAW_RESULT_REASON_CHARACTERS).map(entry => ({
    ...entry,
    message: boundedCollectorReason(entry.message),
  }))
}

function normalizeDuts(value: unknown): DUT[] {
  if (!Array.isArray(value)) return []
  if (value.length > MAX_DUTS) {
    throw new Error(`Manifest DUT count exceeds the ${MAX_DUTS}-entry safety limit`)
  }
  const seen = new Set<string>()
  let collectorRecordCount = 0
  for (const entry of value) {
    if (!isObject(entry) || !isBoundedIdentity(entry.id) || seen.has(entry.id)) {
      throw new Error('Manifest DUT entries must have bounded unique identities')
    }
    seen.add(entry.id)
    if (!Array.isArray(entry.collector_groups)) continue
    for (const group of entry.collector_groups) {
      if (!isObject(group) || !Array.isArray(group.collectors)) continue
      collectorRecordCount += group.collectors.length
      if (collectorRecordCount > MAX_TRACKED_COLLECTOR_RECORDS) {
        throw new Error(
          `Manifest collector records exceed the ${MAX_TRACKED_COLLECTOR_RECORDS}-entry safety limit`,
        )
      }
    }
  }
  return (value as Record<string, any>[]).map(entry => ({
    ...entry,
    status_summary: {
      ...(isObject(entry.status_summary) ? entry.status_summary : {}),
      ...normalizeCollectorLifecycleCounts(entry.status_summary),
    },
    collector_groups: Array.isArray(entry.collector_groups)
      ? entry.collector_groups.map((group: Record<string, any>) => ({
          ...group,
          collectors: Array.isArray(group.collectors)
            ? group.collectors.map((collector: unknown) => {
                if (!isObject(collector)) return collector
                const status = asString(collector.status).toLowerCase()
                const outcomeDetails = ['degraded', 'error', 'partial'].includes(status)
                  ? normalizeCollectorOutcomeDetails(collector.outcome_details)
                  : undefined
                const category =
                  outcomeDetails?.category ??
                  (['degraded', 'error', 'partial'].includes(status) &&
                  COLLECTOR_FAILURE_CATEGORIES.has(collector.failure_category)
                    ? collector.failure_category as CollectorFailureCategory
                    : undefined)
                const normalized: Record<string, any> = {
                  ...collector,
                  reason: boundedCollectorReason(collector.reason),
                }
                delete normalized.failure_category
                delete normalized.outcome_details
                if (category !== undefined) {
                  normalized.failure_category = category
                }
                if (outcomeDetails !== undefined) {
                  normalized.outcome_details = outcomeDetails
                }
                return normalized
              })
            : [],
        }))
      : [],
  })) as DUT[]
}

export function validateAndNormalize(raw: any): Manifest {
  const schemaVersion = raw?.schema_version ?? raw?.version ?? '1.0'
  const generatedAt = asString(raw?.generated_at)
  const rawSummary = isObject(raw?.collection_summary)
    ? raw.collection_summary
    : {
        total_duts: 0, total_collectors_executed: 0,
        total_collectors_in_catalog: 0, total_collectors_filtered_out: 0,
        total_collectors_not_applicable: 0, total_collectors_running: 0,
        total_collectors_pending: 0, total_log_size: 0, total_runtime: 0,
        overall_collection_pct: 0,
        status_counts: { success: 0, degraded: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
      }
  const topLevelHasResult = isObject(raw) && hasOwn(raw, 'run_result')
  const summaryHasResult = hasOwn(rawSummary, 'run_result')
  const topLevelResult = topLevelHasResult
    ? normalizeRunResult(raw.run_result)
    : null
  const summaryResult = summaryHasResult
    ? normalizeRunResult(rawSummary.run_result)
    : null
  if (
    topLevelHasResult &&
    summaryHasResult &&
    !runResultsEqual(topLevelResult, summaryResult)
  ) {
    invalidRunResult('top-level and collection_summary copies differ')
  }
  const runResult = topLevelResult ?? summaryResult
  validateSummaryProjection(rawSummary, runResult)
  const expectedIdentity = runResult?.schema_version === '1.1'
    ? runResult.run_identity
    : null
  const topLevelHasIdentity = isObject(raw) && hasOwn(raw, 'run_identity')
  const summaryHasIdentity = hasOwn(rawSummary, 'run_identity')
  let runIdentity: RunIdentity | null = null
  if (expectedIdentity !== null) {
    if (!topLevelHasIdentity || !summaryHasIdentity) {
      invalidRunResult('identity-bearing manifest is missing a run_identity copy')
    }
    const topLevelIdentity = normalizeRunIdentity(ownDataValue(raw, 'run_identity'))
    const summaryIdentity = normalizeRunIdentity(
      ownDataValue(rawSummary, 'run_identity'),
    )
    if (
      !plainDataEqual(topLevelIdentity, expectedIdentity) ||
      !plainDataEqual(summaryIdentity, expectedIdentity)
    ) {
      invalidRunResult('manifest run_identity copies contradict canonical truth')
    }
    runIdentity = expectedIdentity
  } else if (topLevelHasIdentity || summaryHasIdentity) {
    invalidRunResult('legacy manifest cannot claim a run_identity')
  }
  const collectionSummary = {
    ...rawSummary,
    status_counts: {
      ...(isObject(rawSummary.status_counts) ? rawSummary.status_counts : {}),
      ...normalizeCollectorLifecycleCounts(rawSummary.status_counts),
    },
    ...(runIdentity ? { run_identity: runIdentity } : {}),
    run_result: runResult,
    runtime_status: runResult?.runtime_status ?? null,
    collection_status: runResult?.collection_status ?? null,
    collector_counts: runResult?.collector_counts ?? null,
    ...(runResult ? {
      overall_status: canonicalOverallStatus(runResult, selectionFailureProjection(rawSummary, runResult)),
    } : {}),
  } as CollectionSummary

  if (!SUPPORTED_SCHEMA_VERSIONS.includes(schemaVersion)) {
    console.warn(
      `[ManifestStore] Unknown schema version "${schemaVersion}". ` +
      `Supported: ${SUPPORTED_SCHEMA_VERSIONS.join(', ')}. Attempting graceful load.`
    )
  }

  let toolVersion = raw?.tool_version ?? 'unknown'
  let toolConfig = raw?.tool_config ?? {
    collection_level: 'unknown',
    execution_mode: 'unknown',
    baseboard: 'unknown',
  }
  if (runIdentity !== null) {
    if (toolVersion !== runIdentity.tool.version) {
      invalidRunResult('tool_version contradicts canonical run_identity')
    }
    if (
      !isPlainDataRecord(toolConfig) ||
      toolConfig.collection_level !== runIdentity.invocation.resolved_level ||
      toolConfig.collection_profile !== runIdentity.invocation.resolved_profile
    ) {
      invalidRunResult('tool_config contradicts canonical run_identity')
    }
    toolVersion = runIdentity.tool.version
    toolConfig = {
      ...toolConfig,
      collection_level: runIdentity.invocation.resolved_level,
      collection_profile: runIdentity.invocation.resolved_profile,
    }
  }

  return {
    schema_version: schemaVersion,
    version: raw?.version ?? '1.0',
    generated_at: generatedAt,
    tool_version: toolVersion,
    tool_config: toolConfig,
    duts: normalizeDuts(raw?.duts),
    collector_catalog: Array.isArray(raw?.collector_catalog) ? raw.collector_catalog : [],
    timing: raw?.timing ?? { total_duration: 0, component_timing: {}, per_dut: [], per_service: [] },
    file_index: normalizeFileIndex(raw?.file_index),
    errors: normalizeErrors(raw?.errors),
    preflight: raw?.preflight ?? { per_dut: [] },
    dependency_check: raw?.dependency_check ?? { per_dut: [] },
    extensions: raw?.extensions ?? { per_dut: [] },
    openbmc_coredumps: normalizeOpenBMCCoreDumps(
      raw?.openbmc_coredumps,
      generatedAt,
    ),
    ...(runIdentity ? { run_identity: runIdentity } : {}),
    run_result: runResult,
    collection_summary: collectionSummary,
  }
}

export const useManifestStore = defineStore('manifest', {
  state: () => ({
    manifest: null as Manifest | null,
    loaded: false,
    loadError: null as string | null,
  }),

  getters: {
    duts: (state): DUT[] => state.manifest?.duts ?? [],
    fileIndex: (state): FileEntry[] => state.manifest?.file_index ?? [],
    errors: (state): ErrorEntry[] => state.manifest?.errors ?? [],
    collectorCatalog: (state): CollectorDef[] => state.manifest?.collector_catalog ?? [],
    timing: (state): TimingData | null => state.manifest?.timing ?? null,
    preflight: (state): PreflightData | null => state.manifest?.preflight ?? null,
    dependencyCheck: (state): DependencyCheckData | null => state.manifest?.dependency_check ?? null,
    extensions: (state): ExtensionData | null => state.manifest?.extensions ?? null,
    openBMCCoreDumps: (state): OpenBMCCoreDumpManifest | null =>
      state.manifest?.openbmc_coredumps ?? null,
    collectionSummary: (state): CollectionSummary | null => state.manifest?.collection_summary ?? null,
    runResult: (state): RunResult | null => state.manifest?.run_result ?? null,
    runIdentity: (state): RunIdentity | null => state.manifest?.run_identity ?? null,
    toolVersion: (state): string => state.manifest?.tool_version ?? 'unknown',
    generatedAt: (state): string => state.manifest?.generated_at ?? '',
    schemaVersion: (state): string => state.manifest?.schema_version ?? '1.0',

    dutById: (state) => {
      return (id: string): DUT | undefined =>
        state.manifest?.duts.find(d => d.id === id)
    },

    filesByDut: (state) => {
      return (dutId: string): FileEntry[] =>
        (state.manifest?.file_index ?? []).filter(f => f.dut_id === dutId)
    },

    filesByCollector: (state) => {
      return (collectorId: string): FileEntry[] =>
        (state.manifest?.file_index ?? []).filter(f => f.collector_id === collectorId)
    },

    globalStatusCounts: (state) => {
      if (!state.manifest?.collection_summary) return { success: 0, degraded: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 }
      return state.manifest.collection_summary.status_counts
    },
  },

  actions: {
    async loadInitial(reportProgress?: ReportLoadReporter) {
      this.loaded = false
      this.loadError = null
      clearTimingDocumentCache()
      try {
        let candidate: unknown | null = null
        let standaloneError: unknown = null
        if (typeof location === 'undefined' || location.protocol !== 'file:') {
          try {
            await reportProgress?.({ stage: 'reading', bytesRead: 0 })
            const response = await fetch(new URL('./manifest.json', window.location.href), {
              credentials: 'same-origin',
            })
            candidate = await responseJsonBounded(
              response,
              MAX_MANIFEST_DOCUMENT_BYTES,
              'manifest.json',
              reportProgress,
            )
          } catch (error) {
            standaloneError = error
          }
        }
        if (candidate === null) {
          candidate = await decodeEmbeddedManifest(document, reportProgress)
        }
        if (candidate === null && window.__MANIFEST__) {
          candidate = window.__MANIFEST__
        }
        if (candidate === null) {
          throw standaloneError ?? new Error('No standalone or offline manifest was found')
        }
        await reportProgress?.({ stage: 'validating' })
        this.manifest = validateAndNormalize(candidate)
        this.loaded = true
      } catch (error) {
        this.loadError = `Failed to load manifest: ${error}`
        console.error('[ManifestStore]', this.loadError)
      }
    },

    loadFromWindow() {
      try {
        if (window.__MANIFEST__) {
          clearTimingDocumentCache()
          this.manifest = validateAndNormalize(window.__MANIFEST__)
          this.loaded = true
          this.loadError = null
        }
      } catch (e) {
        this.loadError = `Failed to load manifest: ${e}`
        console.error('[ManifestStore]', this.loadError)
      }
    },

    loadFromJson(data: any) {
      try {
        clearTimingDocumentCache()
        this.manifest = validateAndNormalize(data)
        this.loaded = true
        this.loadError = null
      } catch (e) {
        this.loadError = `Failed to parse manifest: ${e}`
        console.error('[ManifestStore]', this.loadError)
      }
    },

    async loadCollectorTiming(
      dutId: string,
      collectorId: string,
      reference: TimingReference,
    ): Promise<GranularCollectorTiming> {
      const binding = validateTimingReference(reference, dutId, collectorId)
      const cacheKey = timingDocumentCacheKey(binding)
      const timingDocument = await fetchTimingDocument(binding, cacheKey)

      const collectorKey = Object.keys(timingDocument.collectors).find(
        key => key.toUpperCase() === collectorId.toUpperCase(),
      )
      const collectorRecord = collectorKey
        ? timingDocument.collectors[collectorKey]
        : undefined
      if (!isObject(collectorRecord)) {
        throw new Error(`Detailed timing does not contain collector ${collectorId}`)
      }
      const timingCandidate = isObject(collectorRecord.timing)
        ? collectorRecord.timing
        : collectorRecord
      if (
        !isObject(timingCandidate) ||
        !validateGranularTimingShape(
          timingCandidate,
          { operations: 0, artifacts: 0, artifactPaths: 0 },
        )
      ) {
        throw new Error(`Detailed timing for ${collectorId} is malformed`)
      }
      const timing = timingCandidate as GranularCollectorTiming
      // Detailed graphs live only in the bounded LRU and the active view. Do
      // not attach them to the long-lived manifest graph: doing so defeated
      // eviction and retained every DUT document after its Map entry was gone.
      return timing
    },
  },
})
