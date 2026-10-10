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
import {
  CONCURRENCY_SCHEDULER_PATH,
  MAX_CONCURRENCY_SCHEDULER_BYTES,
  ConcurrencySchedulerArtifactInvalidError,
  ConcurrencySchedulerArtifactMissingError,
  loadConcurrencySchedulerArtifact,
} from '@/services/concurrencySchedulerLoader'

const artifact = {
  schema_version: '1.1',
  status: 'completed',
  settings: { mode: 'adaptive', initial_limit: 5 },
  plan_summary: { runnable_collector_operations: 1 },
  decisions: [],
  operation_metrics: { completed_operations: 1 },
}

describe('concurrency scheduler loader', () => {
  it('loads a bounded scheduler artifact from an offline directory', async () => {
    const loaded = await loadConcurrencySchedulerArtifact({
      mode: 'file',
      fileMap: new Map([
        [CONCURRENCY_SCHEDULER_PATH, new File([JSON.stringify(artifact)], 'concurrency_scheduler.json')],
      ]),
    })

    expect(loaded).toEqual(artifact)
  })

  it('reports an absent legacy artifact without treating it as malformed', async () => {
    await expect(loadConcurrencySchedulerArtifact({
      mode: 'file',
      fileMap: new Map(),
    })).rejects.toBeInstanceOf(ConcurrencySchedulerArtifactMissingError)
  })

  it('rejects oversized local evidence before reading it', async () => {
    const file = {
      size: MAX_CONCURRENCY_SCHEDULER_BYTES + 1,
      text: vi.fn(),
    } as unknown as File

    await expect(loadConcurrencySchedulerArtifact({
      mode: 'file',
      fileMap: new Map([[CONCURRENCY_SCHEDULER_PATH, file]]),
    })).rejects.toBeInstanceOf(ConcurrencySchedulerArtifactInvalidError)
    expect(file.text).not.toHaveBeenCalled()
  })

  it('rejects malformed JSON without returning source content', async () => {
    await expect(loadConcurrencySchedulerArtifact({
      mode: 'file',
      fileMap: new Map([[CONCURRENCY_SCHEDULER_PATH, new File(['{secret'], 'concurrency_scheduler.json')]]),
    })).rejects.toMatchObject({
      name: 'ConcurrencySchedulerArtifactInvalidError',
      message: 'Concurrency scheduler evidence is malformed JSON.',
    })
  })

  it('rejects a JSON object that lacks the governed aggregate contract', async () => {
    await expect(loadConcurrencySchedulerArtifact({
      mode: 'file',
      fileMap: new Map([[CONCURRENCY_SCHEDULER_PATH, new File(['{}'], 'concurrency_scheduler.json')]]),
    })).rejects.toMatchObject({
      name: 'ConcurrencySchedulerArtifactInvalidError',
      message: 'Concurrency scheduler evidence is missing required aggregate fields.',
    })
  })

  it('uses the encoded report-relative path and forwards cancellation', async () => {
    const controller = new AbortController()
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe('../.metadata/concurrency_scheduler.json')
      expect(init?.signal).toBe(controller.signal)
      return new Response(JSON.stringify(artifact), { status: 200 })
    })

    const loaded = await loadConcurrencySchedulerArtifact({
      mode: 'http',
      fetcher: fetcher as typeof fetch,
      signal: controller.signal,
    })

    expect(loaded).toEqual(artifact)
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it('rejects an oversized declared HTTP response without reading the body', async () => {
    let cancelled = false
    const response = new Response(new ReadableStream<Uint8Array>({
      cancel() { cancelled = true },
    }), {
      status: 200,
      headers: { 'content-length': String(MAX_CONCURRENCY_SCHEDULER_BYTES + 1) },
    })

    await expect(loadConcurrencySchedulerArtifact({
      mode: 'http',
      fetcher: vi.fn(async () => response) as typeof fetch,
    })).rejects.toBeInstanceOf(ConcurrencySchedulerArtifactInvalidError)
    expect(cancelled).toBe(true)
  })

  it('maps HTTP 404 to the legacy missing-artifact state', async () => {
    await expect(loadConcurrencySchedulerArtifact({
      mode: 'http',
      fetcher: vi.fn(async () => new Response(null, { status: 404 })) as typeof fetch,
    })).rejects.toBeInstanceOf(ConcurrencySchedulerArtifactMissingError)
  })
})
