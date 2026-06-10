import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach } from 'vitest'
import { useFileSystemStore } from '@/stores/fileSystem'

describe('fileSystem store', () => {
  beforeEach(() => setActivePinia(createPinia()))

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
    expect(store.integrityStatus?.found).toBe(1)
    expect(store.integrityStatus?.missing).toEqual(['DUT_1/host/missing.log'])
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
})
