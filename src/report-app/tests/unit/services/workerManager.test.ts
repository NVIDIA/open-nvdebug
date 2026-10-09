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
import { createInlineWorker } from '@/services/workerManager'

describe('createInlineWorker', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('creates a blob worker and revokes its URL on a load error', () => {
    const revokeObjectURL = vi.fn()
    const addEventListener = vi.fn()
    const terminate = vi.fn()
    const postMessage = vi.fn()
    const workerUrls: string[] = []
    class WorkerStub {
      onmessage = null
      addEventListener = addEventListener
      terminate = terminate
      postMessage = postMessage

      constructor(url: string) {
        workerUrls.push(url)
      }
    }
    vi.stubGlobal('Worker', WorkerStub)
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn(() => 'blob:nvdebug-worker'),
      revokeObjectURL,
    })

    const result = createInlineWorker('self.onmessage = () => undefined')

    expect(result).toBeInstanceOf(WorkerStub)
    expect(workerUrls).toEqual(['blob:nvdebug-worker'])
    expect(addEventListener).toHaveBeenCalledWith(
      'error',
      expect.any(Function),
      { once: true },
    )
    const errorListener = addEventListener.mock.calls[0][1] as () => void
    errorListener()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:nvdebug-worker')
  })

  it('falls back to an idle callback and returns transformed data', () => {
    const idleCallbacks: Array<() => void> = []
    class BlockedWorker {
      constructor() {
        throw new Error('blocked')
      }
    }
    vi.stubGlobal('Worker', BlockedWorker)
    vi.stubGlobal('requestIdleCallback', (callback: () => void) => {
      idleCallbacks.push(callback)
      return 1
    })
    const fallback = createInlineWorker('ignored', (value: number) => value * 2)
    const received = vi.fn()
    fallback.onmessage = received

    fallback.postMessage(21)
    expect(received).not.toHaveBeenCalled()
    idleCallbacks.shift()?.()

    expect(received).toHaveBeenCalledWith(expect.objectContaining({ data: 42 }))
    fallback.terminate()
    expect(fallback.onmessage).toBeNull()
  })

  it('uses a timer fallback and serializes handler errors', () => {
    vi.useFakeTimers()
    class BlockedWorker {
      constructor() {
        throw new Error('blocked')
      }
    }
    vi.stubGlobal('Worker', BlockedWorker)
    vi.stubGlobal('requestIdleCallback', undefined)
    const fallback = createInlineWorker('ignored', () => {
      throw new TypeError('bad worker input')
    })
    const received = vi.fn()
    fallback.onmessage = received

    fallback.postMessage({ unsafe: false })
    vi.runAllTimers()

    expect(received).toHaveBeenCalledWith(
      expect.objectContaining({ data: { error: 'TypeError: bad worker input' } }),
    )
  })

  it('echoes data when no fallback handler was supplied', () => {
    vi.useFakeTimers()
    class BlockedWorker {
      constructor() {
        throw new Error('blocked')
      }
    }
    vi.stubGlobal('Worker', BlockedWorker)
    vi.stubGlobal('requestIdleCallback', undefined)
    const fallback = createInlineWorker('ignored')
    const received = vi.fn()
    fallback.onmessage = received

    fallback.postMessage('payload')
    vi.runAllTimers()

    expect(received).toHaveBeenCalledWith(
      expect.objectContaining({ data: 'payload' }),
    )
  })
})
