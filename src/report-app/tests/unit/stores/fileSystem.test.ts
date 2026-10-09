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

import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { useFileSystemStore } from '@/stores/fileSystem'

describe('fileSystem store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  afterEach(() => vi.unstubAllGlobals())

  it('detects mode from protocol', () => {
    const store = useFileSystemStore()
    // jsdom defaults to about:blank, so mode detection falls to http
    expect(['file', 'http']).toContain(store.mode)
  })

  it('starts with no directory loaded', () => {
    const store = useFileSystemStore()
    expect(store.directoryLoaded).toBe(false)
    expect(store.fileMap.size).toBe(0)
  })

  it('checks integrity and reports missing files', () => {
    const store = useFileSystemStore()
    store.fileMap.set('DUT_1/redfish/Systems.json', new File([], 'Systems.json'))
    store.directoryLoaded = true

    store.checkIntegrity([
      { path: 'DUT_1/redfish/Systems.json', size: 100, type: 'json', collector_id: 'R1', dut_id: 'DUT_1', collector_group: 'redfish', collector_name: 'Systems' },
      { path: 'DUT_1/host/missing.log', size: 200, type: 'log', collector_id: 'H1', dut_id: 'DUT_1', collector_group: 'host', collector_name: 'missing' },
    ])

    expect(store.integrityStatus?.total).toBe(2)
    expect(store.integrityStatus?.checked).toBe(2)
    expect(store.integrityStatus?.found).toBe(1)
    expect(store.integrityStatus?.missing).toEqual(['DUT_1/host/missing.log'])
    expect(store.integrityStatus?.unknown).toEqual([])
    expect(store.integrityStatus?.truncated).toBe(0)
    expect(store.integrityOk).toBe(false)
  })

  it('reports integrity ok when all files found', () => {
    const store = useFileSystemStore()
    store.fileMap.set('a.json', new File([], 'a.json'))
    store.directoryLoaded = true

    store.checkIntegrity([
      { path: 'a.json', size: 100, type: 'json', collector_id: 'R1', dut_id: 'D1', collector_group: 'redfish', collector_name: 'a' },
    ])

    expect(store.integrityOk).toBe(true)
  })

  it('detects a missing HTTP artifact with bounded HEAD probes', async () => {
    const browserWindow = window
    vi.stubGlobal('window', {
      location: new URL('http://localhost/reports/index.html'),
      setTimeout: browserWindow.setTimeout.bind(browserWindow),
      clearTimeout: browserWindow.clearTimeout.bind(browserWindow),
    })
    const fetchMock = vi.fn(async (input: URL | RequestInfo) => {
      const missing = String(input).endsWith('/DUT_1/host/missing.log')
      return {
        status: missing ? 404 : 200,
        ok: !missing,
        body: null,
      } as Response
    })
    vi.stubGlobal('fetch', fetchMock)
    const store = useFileSystemStore()
    store.mode = 'http'

    await store.checkHttpIntegrity([
      { path: 'DUT_1/redfish/Systems.json', size: 100, type: 'json', collector_id: 'R1', dut_id: 'DUT_1', collector_group: 'redfish', collector_name: 'Systems' },
      { path: 'DUT_1/host/missing.log', size: 200, type: 'log', collector_id: 'H1', dut_id: 'DUT_1', collector_group: 'host', collector_name: 'missing' },
    ])

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls.map(([input]) => String(input))).toContain(
      'http://localhost/DUT_1/host/missing.log',
    )
    expect(fetchMock.mock.calls.every(([, init]) => init?.method === 'HEAD')).toBe(true)
    expect(store.integrityStatus?.missing).toEqual(['DUT_1/host/missing.log'])
    expect(store.integrityStatus?.checked).toBe(2)
    expect(store.integrityOk).toBe(false)
  })

  it('retains incomplete status and bounded probes for a large report without missing files', async () => {
    const browserWindow = window
    vi.stubGlobal('window', {
      location: new URL('http://localhost/reports/index.html'),
      setTimeout: browserWindow.setTimeout.bind(browserWindow),
      clearTimeout: browserWindow.clearTimeout.bind(browserWindow),
    })
    const fetchMock = vi.fn(async () => ({ status: 200, ok: true, body: null } as Response))
    vi.stubGlobal('fetch', fetchMock)
    const store = useFileSystemStore()
    store.mode = 'http'
    const fileIndex = Array.from({ length: 18087 }, (_, index) => ({
      path: `DUT_1/host/file-${index}.log`,
      size: 100,
      type: 'log',
      collector_id: 'H1',
      dut_id: 'DUT_1',
      collector_group: 'host',
      collector_name: 'Host logs',
    }))

    await store.checkHttpIntegrity(fileIndex)

    expect(fetchMock).toHaveBeenCalledTimes(2048)
    expect(store.integrityStatus).toEqual({
      total: 18087,
      checked: 2048,
      found: 2048,
      missing: [],
      unknown: [],
      truncated: 16039,
    })
    expect(store.integrityOk).toBe(false)
  })
})
