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

export const CONCURRENCY_SCHEDULER_PATH = '.metadata/concurrency_scheduler.json'
export const MAX_CONCURRENCY_SCHEDULER_BYTES = 2 * 1024 * 1024

type JsonRecord = Record<string, unknown>

export interface ConcurrencySchedulerFileAccess {
  mode: 'http' | 'file'
  fileMap?: Map<string, File>
  fetcher?: typeof fetch
  signal?: AbortSignal
}

export class ConcurrencySchedulerArtifactMissingError extends Error {
  constructor(message = 'Concurrency scheduler evidence is not present in this run.') {
    super(message)
    this.name = 'ConcurrencySchedulerArtifactMissingError'
  }
}

export class ConcurrencySchedulerArtifactInvalidError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConcurrencySchedulerArtifactInvalidError'
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  signal?.throwIfAborted()
}

function artifactUrl(): string {
  return `../${CONCURRENCY_SCHEDULER_PATH.split('/').map(encodeURIComponent).join('/')}`
}

function isNonEmptyRecord(value: unknown): value is JsonRecord {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length > 0
}

function parseRoot(text: string): JsonRecord {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence is malformed JSON.')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence must have an object root.')
  }
  const root = parsed as JsonRecord
  if (
    Object.keys(root).length === 0
    || !isNonEmptyRecord(root.settings)
    || !isNonEmptyRecord(root.plan_summary)
    || !Array.isArray(root.decisions)
    || !isNonEmptyRecord(root.operation_metrics)
  ) {
    throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence is missing required aggregate fields.')
  }
  return root
}

async function loadLocal(access: ConcurrencySchedulerFileAccess): Promise<JsonRecord> {
  throwIfAborted(access.signal)
  const file = access.fileMap?.get(CONCURRENCY_SCHEDULER_PATH)
  if (!file) throw new ConcurrencySchedulerArtifactMissingError()
  if (file.size > MAX_CONCURRENCY_SCHEDULER_BYTES) {
    throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence exceeds the browser safety limit.')
  }
  const text = await file.text()
  throwIfAborted(access.signal)
  if (new TextEncoder().encode(text).byteLength > MAX_CONCURRENCY_SCHEDULER_BYTES) {
    throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence exceeds the browser safety limit.')
  }
  return parseRoot(text)
}

async function loadHttp(access: ConcurrencySchedulerFileAccess): Promise<JsonRecord> {
  throwIfAborted(access.signal)
  const fetcher = access.fetcher ?? fetch
  const response = await fetcher(artifactUrl(), { signal: access.signal })
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined)
    throw new ConcurrencySchedulerArtifactMissingError()
  }
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined)
    throw new ConcurrencySchedulerArtifactInvalidError(`Concurrency scheduler evidence could not be loaded (HTTP ${response.status}).`)
  }
  const declaredLength = response.headers.get('content-length')
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength)
    if (Number.isFinite(parsedLength) && parsedLength > MAX_CONCURRENCY_SCHEDULER_BYTES) {
      await response.body?.cancel().catch(() => undefined)
      throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence exceeds the browser safety limit.')
    }
  }
  if (!response.body) {
    throw new ConcurrencySchedulerArtifactInvalidError('The browser did not provide a bounded scheduler evidence stream.')
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      throwIfAborted(access.signal)
      const chunk = await reader.read()
      if (chunk.done) break
      if (!chunk.value || chunk.value.byteLength === 0) continue
      total += chunk.value.byteLength
      if (total > MAX_CONCURRENCY_SCHEDULER_BYTES) {
        throw new ConcurrencySchedulerArtifactInvalidError('Concurrency scheduler evidence exceeds the browser safety limit.')
      }
      chunks.push(chunk.value.slice())
    }
  } finally {
    await reader.cancel().catch(() => undefined)
  }
  throwIfAborted(access.signal)
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return parseRoot(new TextDecoder().decode(bytes))
}

export async function loadConcurrencySchedulerArtifact(
  access: ConcurrencySchedulerFileAccess,
): Promise<JsonRecord> {
  return access.mode === 'file' ? loadLocal(access) : loadHttp(access)
}
