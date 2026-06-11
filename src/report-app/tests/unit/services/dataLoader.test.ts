import { describe, it, expect, beforeEach, vi } from 'vitest'
import { DataLoader } from '@/services/dataLoader'
import type { FileRef } from '@/types/manifest'

function makeRef(path: string, size = 100): FileRef {
  return { path, size, type: 'json', collector_id: 'R1' }
}

describe('DataLoader', () => {
  let loader: DataLoader

  beforeEach(() => {
    loader = new DataLoader('http')
    vi.restoreAllMocks()
  })

  describe('HTTP mode', () => {
    it('fetches file via fetch()', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve('{"test": true}'),
      })
      vi.stubGlobal('fetch', mockFetch)

      const content = await loader.loadFile(makeRef('DUT_1/redfish/Systems.json'))
      expect(content).toBe('{"test": true}')
      expect(mockFetch).toHaveBeenCalledWith(
        '../DUT_1/redfish/Systems.json',
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      )
    })

    it('throws on HTTP error', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404, statusText: 'Not Found' }))
      await expect(loader.loadFile(makeRef('missing.json'))).rejects.toThrow('HTTP 404')
    })

    it('sends Range header for slice requests', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
        ok: true,
        status: 206,
        text: () => Promise.resolve('partial content'),
      }))

      const content = await loader.loadFileSlice(makeRef('big.log'), 100, 200)
      expect(content).toBe('partial content')
      expect(fetch).toHaveBeenCalledWith(
        '../big.log',
        expect.objectContaining({
          headers: { Range: 'bytes=100-200' },
          signal: expect.any(AbortSignal),
        }),
      )
    })
  })

  describe('file:// mode', () => {
    it('reads from fileMap', async () => {
      loader = new DataLoader('file')
      const mockFile = new File(['hello world'], 'test.txt', { type: 'text/plain' })
      loader.setFileMap(new Map([['test.txt', mockFile]]))

      const content = await loader.loadFile(makeRef('test.txt'))
      expect(content).toBe('hello world')
    })

    it('throws when file not in fileMap', async () => {
      loader = new DataLoader('file')
      loader.setFileMap(new Map())
      await expect(loader.loadFile(makeRef('missing.txt'))).rejects.toThrow('File not found')
    })

    it('reads file slice', async () => {
      loader = new DataLoader('file')
      const mockFile = new File(['0123456789'], 'data.txt', { type: 'text/plain' })
      loader.setFileMap(new Map([['data.txt', mockFile]]))

      const content = await loader.loadFileSlice(makeRef('data.txt'), 0, 5)
      expect(content).toBe('01234')
    })
  })

  describe('LRU cache', () => {
    it('returns cached content on second load', async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve('data') })
      vi.stubGlobal('fetch', mockFetch)

      await loader.loadFile(makeRef('file.json'))
      await loader.loadFile(makeRef('file.json'))

      expect(mockFetch).toHaveBeenCalledTimes(1) // Only fetched once
    })

    it('evicts oldest when cache is full', async () => {
      // Create loader with tiny cache (200 bytes)
      loader = new DataLoader('http')
      // Access private cache for testing — use a small cache
      ;(loader as any).cache = new (loader as any).cache.constructor(200)

      vi.stubGlobal('fetch', vi.fn().mockImplementation((path: string) => ({
        ok: true,
        text: () => Promise.resolve('x'.repeat(100)), // ~264 bytes per entry
      })))

      await loader.loadFile(makeRef('a.json'))
      await loader.loadFile(makeRef('b.json')) // Should evict a.json

      // b.json should be cached
      vi.mocked(fetch).mockClear()
      await loader.loadFile(makeRef('b.json'))
      expect(fetch).not.toHaveBeenCalled()

      // a.json should NOT be cached (was evicted)
      await loader.loadFile(makeRef('a.json'))
      expect(fetch).toHaveBeenCalledTimes(1)
    })
  })

  describe('concurrency control', () => {
    it('limits concurrent loads to 3', async () => {
      let activeCount = 0
      let maxActive = 0

      vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => {
        activeCount++
        maxActive = Math.max(maxActive, activeCount)
        await new Promise(r => setTimeout(r, 50))
        activeCount--
        return { ok: true, text: () => Promise.resolve('data') }
      }))

      const promises = Array.from({ length: 6 }, (_, i) =>
        loader.loadFile(makeRef(`file${i}.json`))
      )
      await Promise.all(promises)

      expect(maxActive).toBeLessThanOrEqual(3)
    })
  })

  describe('cancellation', () => {
    it('aborts in-flight request', async () => {
      const abortFn = vi.fn()
      vi.stubGlobal('fetch', vi.fn().mockImplementation((_, opts) => {
        opts?.signal?.addEventListener('abort', abortFn)
        return new Promise(() => {}) // Never resolves
      }))

      const promise = loader.loadFile(makeRef('slow.json'))
      // Allow microtasks to run so fetch is actually called
      await new Promise(r => setTimeout(r, 0))
      loader.cancelLoad('slow.json')

      expect(abortFn).toHaveBeenCalled()
    })
  })
})
