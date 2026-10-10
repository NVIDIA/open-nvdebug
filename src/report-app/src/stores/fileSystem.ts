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
import type { FileEntry } from '@/types/manifest'

const MAX_HTTP_INTEGRITY_ENTRIES = 2_048
const MAX_HTTP_INTEGRITY_REQUESTS = MAX_HTTP_INTEGRITY_ENTRIES * 2
const HTTP_INTEGRITY_CONCURRENCY = 4
const HTTP_INTEGRITY_REQUEST_TIMEOUT_MS = 3_000
const HTTP_INTEGRITY_OVERALL_TIMEOUT_MS = 15_000
const MAX_HTTP_INTEGRITY_PATH_CHARACTERS = 4_096

let activeHttpIntegrityController: AbortController | null = null
let httpIntegrityGeneration = 0

type IntegrityStatus = {
  total: number
  checked: number
  found: number
  missing: string[]
  unknown: string[]
  truncated: number
}

type HttpIntegrityResult = 'found' | 'missing' | 'unknown'

export function reportArtifactUrl(path: string): URL | null {
  if (!path || path.length > MAX_HTTP_INTEGRITY_PATH_CHARACTERS) return null
  const segments = path.split('/')
  if (segments.some(segment => (
    !segment || segment === '.' || segment === '..' || segment.includes('\\') ||
    [...segment].some(character => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint <= 31 || codePoint === 127
    })
  ))) return null
  const encodedPath = segments.map(encodeURIComponent).join('/')
  try {
    // Manifest file_index paths are relative to the nvdebug_logs_* root. The
    // SPA is its reports/index.html child, so artifacts are one level above it.
    const url = new URL(`../${encodedPath}`, window.location.href)
    return url.origin === window.location.origin ? url : null
  } catch {
    return null
  }
}

async function probeHttpArtifact(
  url: URL,
  method: 'HEAD' | 'GET',
  overallSignal: AbortSignal,
): Promise<{ result: HttpIntegrityResult; allowFallback: boolean }> {
  const controller = new AbortController()
  const abortRequest = () => controller.abort()
  overallSignal.addEventListener('abort', abortRequest, { once: true })
  const timeout = window.setTimeout(abortRequest, HTTP_INTEGRITY_REQUEST_TIMEOUT_MS)
  try {
    const response = await fetch(url, {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: method === 'GET' ? { Range: 'bytes=0-0' } : undefined,
      signal: controller.signal,
    })
    try {
      if (response.status === 404 || response.status === 410) {
        return { result: 'missing', allowFallback: false }
      }
      if (response.ok) return { result: 'found', allowFallback: false }
      return {
        result: 'unknown',
        allowFallback: method === 'HEAD' && [405, 501].includes(response.status),
      }
    } finally {
      try { await response.body?.cancel() } catch { /* retain the probe result */ }
    }
  } catch {
    return { result: 'unknown', allowFallback: false }
  } finally {
    window.clearTimeout(timeout)
    overallSignal.removeEventListener('abort', abortRequest)
  }
}

export const useFileSystemStore = defineStore('fileSystem', {
  state: () => ({
    mode: (typeof location !== 'undefined' && location.protocol === 'file:' ? 'file' : 'http') as 'file' | 'http',
    fileMap: new Map<string, File>(),
    directoryLoaded: false,
    integrityStatus: null as IntegrityStatus | null,
  }),

  getters: {
    needsDirectoryPicker: (state): boolean => state.mode === 'file' && !state.directoryLoaded,
    integrityOk: (state): boolean => (
      state.integrityStatus !== null &&
      state.integrityStatus.checked === state.integrityStatus.total &&
      state.integrityStatus.missing.length === 0 &&
      state.integrityStatus.unknown.length === 0 &&
      state.integrityStatus.truncated === 0
    ),
  },

  actions: {
    loadDirectory(fileList: FileList) {
      this.fileMap.clear()
      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i]
        const relativePath = (file as any).webkitRelativePath as string
        if (relativePath) {
          const parts = relativePath.split('/')
          const pathWithoutRoot = parts.slice(1).join('/')
          if (pathWithoutRoot) {
            this.fileMap.set(pathWithoutRoot, file)
          }
        }
      }
      this.directoryLoaded = true
    },

    /**
     * Load files from a drag-drop. Accepts the DataTransferItemList from the
     * drop event. Walks any dropped directory entries recursively, stripping
     * the top-level directory so file paths match manifest entries.
     */
    async loadDirectoryFromDataTransfer(items: DataTransferItemList): Promise<void> {
      const entries: FileSystemEntry[] = []
      for (let i = 0; i < items.length; i++) {
        const entry = (items[i] as any).webkitGetAsEntry?.() as FileSystemEntry | null
        if (entry) entries.push(entry)
      }
      if (entries.length === 0) {
        throw new Error('Nothing droppable. Try dragging the folder itself, not its contents.')
      }
      const dirEntries = entries.filter((e) => e.isDirectory)
      if (dirEntries.length === 0) {
        throw new Error('Please drop a folder, not individual files.')
      }

      this.fileMap.clear()
      for (const dirEntry of dirEntries) {
        await collectFiles(dirEntry, this.fileMap)
      }
      this.directoryLoaded = true
    },

    checkIntegrity(fileIndex: FileEntry[]) {
      const missing: string[] = []
      for (const entry of fileIndex) {
        if (!this.fileMap.has(entry.path)) {
          missing.push(entry.path)
        }
      }
      this.integrityStatus = {
        total: fileIndex.length,
        checked: fileIndex.length,
        found: fileIndex.length - missing.length,
        missing,
        unknown: [],
        truncated: 0,
      }
    },

    /**
     * Verify manifest-listed artifacts when a report is served over HTTP.
     *
     * The scan is deliberately same-origin, request-bounded, time-bounded, and
     * concurrency-bounded because the manifest is collection-controlled input.
     * HEAD avoids downloading artifacts; servers that reject HEAD get one
     * bounded range-GET fallback whose body is cancelled without consumption.
     * Indeterminate and capped entries remain visible as an incomplete check
     * instead of being reported as present.
     */
    async checkHttpIntegrity(fileIndex: FileEntry[]): Promise<void> {
      if (this.mode !== 'http') return
      this.cancelHttpIntegrityCheck()
      const generation = ++httpIntegrityGeneration
      const controller = new AbortController()
      activeHttpIntegrityController = controller
      const overallTimeout = window.setTimeout(
        () => controller.abort(),
        HTTP_INTEGRITY_OVERALL_TIMEOUT_MS,
      )
      const selected = fileIndex.slice(0, MAX_HTTP_INTEGRITY_ENTRIES)
      const results: HttpIntegrityResult[] = selected.map(() => 'unknown')
      let nextIndex = 0
      let requestCount = 0

      const worker = async () => {
        while (!controller.signal.aborted) {
          const index = nextIndex++
          if (index >= selected.length) return
          const url = reportArtifactUrl(selected[index].path)
          if (!url || requestCount >= MAX_HTTP_INTEGRITY_REQUESTS) continue
          requestCount += 1
          let probe = await probeHttpArtifact(url, 'HEAD', controller.signal)
          if (
            probe.allowFallback && !controller.signal.aborted &&
            requestCount < MAX_HTTP_INTEGRITY_REQUESTS
          ) {
            requestCount += 1
            probe = await probeHttpArtifact(url, 'GET', controller.signal)
          }
          results[index] = probe.result
        }
      }

      try {
        const workerCount = Math.min(HTTP_INTEGRITY_CONCURRENCY, selected.length)
        await Promise.all(Array.from({ length: workerCount }, worker))
      } finally {
        window.clearTimeout(overallTimeout)
      }
      if (generation !== httpIntegrityGeneration) return
      activeHttpIntegrityController = null

      const missing = selected
        .filter((_, index) => results[index] === 'missing')
        .map(entry => entry.path)
      const unknown = selected
        .filter((_, index) => results[index] === 'unknown')
        .map(entry => entry.path)
      const found = results.filter(result => result === 'found').length
      this.integrityStatus = {
        total: fileIndex.length,
        checked: found + missing.length,
        found,
        missing,
        unknown,
        truncated: fileIndex.length - selected.length,
      }
    },

    cancelHttpIntegrityCheck() {
      httpIntegrityGeneration += 1
      activeHttpIntegrityController?.abort()
      activeHttpIntegrityController = null
    },

    /**
     * Quick post-selection sanity check. Returns true if at least one manifest
     * file was resolved in the picked/dropped directory. Callers use this to
     * reject wrong-folder picks with a helpful error rather than silently
     * accepting a useless selection.
     */
    validateAgainstManifest(fileIndex: FileEntry[]): { matched: number; total: number; sample: string[] } {
      let matched = 0
      for (const entry of fileIndex) {
        if (this.fileMap.has(entry.path)) matched++
      }
      const sample = fileIndex.slice(0, 3).map((e) => e.path)
      return { matched, total: fileIndex.length, sample }
    },

    getFile(path: string): File | undefined {
      return this.fileMap.get(path)
    },

    reset() {
      this.cancelHttpIntegrityCheck()
      this.fileMap.clear()
      this.directoryLoaded = false
      this.integrityStatus = null
    },
  },
})

// Recursively walk a FileSystemDirectoryEntry and populate `map` with File
// objects keyed by their path relative to the dropped directory (the top-
// level directory name is stripped to match manifest entries).
async function collectFiles(root: FileSystemEntry, map: Map<string, File>): Promise<void> {
  const rootPrefix = root.fullPath.replace(/^\//, '') + '/'
  const stack: FileSystemEntry[] = [root]
  while (stack.length) {
    const entry = stack.pop()!
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => {
        ;(entry as FileSystemFileEntry).file(resolve, reject)
      })
      // entry.fullPath starts with '/<root>/...'; strip the leading slash and
      // the root directory segment to match how webkitRelativePath is stripped.
      const rel = entry.fullPath.replace(/^\//, '')
      const relWithoutRoot = rel.startsWith(rootPrefix) ? rel.slice(rootPrefix.length) : rel
      if (relWithoutRoot) map.set(relWithoutRoot, file)
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      // readEntries() only returns a batch; loop until empty.
      while (true) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => {
          reader.readEntries(resolve, reject)
        })
        if (batch.length === 0) break
        stack.push(...batch)
      }
    }
  }
}
