import type { FileRef } from '@/types/manifest'

/**
 * Size-bounded LRU cache that evicts by total byte size, not entry count.
 */
class SizeBoundedLRUCache {
  private cache = new Map<string, string>()
  private currentBytes = 0
  private readonly maxBytes: number

  constructor(maxBytes: number) {
    this.maxBytes = maxBytes
  }

  get(key: string): string | undefined {
    const value = this.cache.get(key)
    if (value !== undefined) {
      // Move to end (most recently used)
      this.cache.delete(key)
      this.cache.set(key, value)
    }
    return value
  }

  set(key: string, value: string): void {
    // Remove existing entry if present
    if (this.cache.has(key)) {
      const existing = this.cache.get(key)!
      this.currentBytes -= this.sizeOf(existing)
      this.cache.delete(key)
    }

    const entrySize = this.sizeOf(value)

    // Evict oldest entries until we have room
    while (this.currentBytes + entrySize > this.maxBytes && this.cache.size > 0) {
      const oldest = this.cache.keys().next().value!
      const oldestValue = this.cache.get(oldest)!
      this.currentBytes -= this.sizeOf(oldestValue)
      this.cache.delete(oldest)
    }

    this.cache.set(key, value)
    this.currentBytes += entrySize
  }

  has(key: string): boolean {
    return this.cache.has(key)
  }

  clear(): void {
    this.cache.clear()
    this.currentBytes = 0
  }

  get size(): number {
    return this.cache.size
  }

  get bytes(): number {
    return this.currentBytes
  }

  private sizeOf(value: string): number {
    return value.length * 2 + 64 // UTF-16 chars + object overhead
  }
}

export type DataLoaderMode = 'http' | 'file'

export class DataLoader {
  private cache: SizeBoundedLRUCache
  private mode: DataLoaderMode
  private fileMap: Map<string, File>
  private abortControllers = new Map<string, AbortController>()
  private activeLoads = 0
  private readonly maxConcurrent = 3
  private loadQueue: Array<() => void> = []

  constructor(mode?: DataLoaderMode) {
    this.mode = mode ?? (typeof location !== 'undefined' && location.protocol === 'file:' ? 'file' : 'http')
    this.cache = new SizeBoundedLRUCache(100 * 1024 * 1024) // 100MB
    this.fileMap = new Map()
  }

  getMode(): DataLoaderMode {
    return this.mode
  }

  setFileMap(fileMap: Map<string, File>): void {
    this.fileMap = fileMap
  }

  async loadFile(ref: FileRef): Promise<string> {
    // Check cache
    const cached = this.cache.get(ref.path)
    if (cached !== undefined) return cached

    // Wait for concurrency slot
    await this.acquireSlot()

    try {
      let content: string
      if (this.mode === 'http') {
        content = await this.fetchFile(ref.path)
      } else {
        content = await this.readFromFileMap(ref.path)
      }
      this.cache.set(ref.path, content)
      return content
    } finally {
      this.releaseSlot()
    }
  }

  async loadFileSlice(ref: FileRef, start: number, end: number): Promise<string> {
    await this.acquireSlot()

    try {
      if (this.mode === 'http') {
        return await this.fetchFileRange(ref.path, start, end)
      } else {
        return await this.readFileSlice(ref.path, start, end)
      }
    } finally {
      this.releaseSlot()
    }
  }

  cancelLoad(path: string): void {
    const controller = this.abortControllers.get(path)
    if (controller) {
      controller.abort()
      this.abortControllers.delete(path)
    }
  }

  clearCache(): void {
    this.cache.clear()
  }

  get cacheSize(): number {
    return this.cache.bytes
  }

  // --- Private methods ---

  private async fetchFile(path: string): Promise<string> {
    const controller = new AbortController()
    this.abortControllers.set(path, controller)
    try {
      // SPA lives in reports/ — file paths are relative to the parent (log_dir)
      const url = '../' + path
      const resp = await fetch(url, { signal: controller.signal })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`)
      return await resp.text()
    } finally {
      this.abortControllers.delete(path)
    }
  }

  private async fetchFileRange(path: string, start: number, end: number): Promise<string> {
    const controller = new AbortController()
    this.abortControllers.set(path, controller)
    try {
      const url = '../' + path
      const resp = await fetch(url, {
        headers: { Range: `bytes=${start}-${end}` },
        signal: controller.signal,
      })
      // Graceful degradation: server may not support Range
      if (resp.status === 206 || resp.ok) {
        return await resp.text()
      }
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`)
    } finally {
      this.abortControllers.delete(path)
    }
  }

  private async readFromFileMap(path: string): Promise<string> {
    const file = this.fileMap.get(path)
    if (!file) throw new Error(`File not found in directory: ${path}`)
    return await file.text()
  }

  private async readFileSlice(path: string, start: number, end: number): Promise<string> {
    const file = this.fileMap.get(path)
    if (!file) throw new Error(`File not found in directory: ${path}`)
    const blob = file.slice(start, end)
    return await blob.text()
  }

  private acquireSlot(): Promise<void> {
    if (this.activeLoads < this.maxConcurrent) {
      this.activeLoads++
      return Promise.resolve()
    }
    return new Promise<void>((resolve) => {
      this.loadQueue.push(() => {
        this.activeLoads++
        resolve()
      })
    })
  }

  private releaseSlot(): void {
    this.activeLoads--
    const next = this.loadQueue.shift()
    if (next) next()
  }
}
