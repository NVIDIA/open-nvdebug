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

import {
  MAX_LOG_LINE_CHARACTERS,
  MAX_LOG_PREVIEW_CHARACTERS,
  MAX_LOG_PREVIEW_LINES,
  parseLogLine,
} from '@/utils/logLines'

export const MAX_RUNTIME_LOG_SCAN_BYTES = 128 * 1024 * 1024
const SCAN_CHUNK_BYTES = 64 * 1024
const PAINT_INTERVAL_BYTES = 256 * 1024

interface RuntimeLogAccess {
  mode: 'http' | 'file'
  fileMap?: Map<string, File>
  signal: AbortSignal
  onProgress?: (bytesRead: number) => void
}

export interface CollectorLogPreview {
  content: string
  lineCount: number
  bytesRead: number
  scanLimited: boolean
  previewLimited: boolean
  longLinesTruncated: boolean
}

function artifactUrl(path: string): string {
  const segments = path.split('/')
  if (path.length > 4096 || segments.some(segment => (
    !segment || segment === '.' || segment === '..' || segment.includes('\\') ||
    [...segment].some(character => character.charCodeAt(0) <= 31 || character.charCodeAt(0) === 127)
  ))) throw new Error('The runtime log path is invalid.')
  return `../${segments.map(encodeURIComponent).join('/')}`
}

async function openLog(path: string, access: RuntimeLogAccess): Promise<ReadableStream<Uint8Array>> {
  const url = artifactUrl(path)
  access.signal.throwIfAborted()
  if (access.mode === 'file') {
    const file = access.fileMap?.get(path)
    if (!file) throw new Error('The runtime log is missing from the selected report folder.')
    return file.stream()
  }
  const response = await fetch(url, { signal: access.signal, redirect: 'error', credentials: 'same-origin' })
  if (!response.ok || response.status === 206) {
    await response.body?.cancel().catch(() => undefined)
    throw new Error(`The runtime log could not be loaded (HTTP ${response.status}).`)
  }
  if (!response.body) throw new Error('The browser could not read the runtime log as a stream.')
  return response.body
}

/** Scan the DUT log before applying preview limits so late collectors are found. */
export async function loadCollectorRuntimeLogs(
  path: string,
  collectorId: string,
  access: RuntimeLogAccess,
): Promise<CollectorLogPreview> {
  const stream = await openLog(path, access)
  const reader = stream.getReader()
  const cancel = () => { void reader.cancel().catch(() => undefined) }
  access.signal.addEventListener('abort', cancel, { once: true })
  const decoder = new TextDecoder()
  const lines: string[] = []
  const wantedId = collectorId.toUpperCase()
  let belongsToCollector = false
  let pending = ''
  let bytesRead = 0
  let lastPaintBytes = 0
  let storedCharacters = 0
  let scanLimited = false
  let previewLimited = false
  let longLinesTruncated = false

  function finishLine(): void {
    const parsed = parseLogLine(pending.replace(/\r$/, ''))
    const startsRecord = parsed.timestamp !== null ||
      /^\[[^\]\r\n]{1,128}\][ \t]+\[(?:DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|TRACE)\]/.test(pending) ||
      /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})? - /.test(pending)
    pending = ''
    // Untagged records reset ownership. Only continuation lines inherit the
    // preceding record; collector names mentioned in message text never match.
    if (startsRecord) {
      belongsToCollector = parsed.collectorId?.toUpperCase() === wantedId
    }
    if (!belongsToCollector) return
    if (
      lines.length >= MAX_LOG_PREVIEW_LINES ||
      storedCharacters + parsed.raw.length + 1 > MAX_LOG_PREVIEW_CHARACTERS
    ) {
      previewLimited = true
      return
    }
    lines.push(parsed.raw)
    storedCharacters += parsed.raw.length + 1
    longLinesTruncated ||= parsed.truncated
  }

  function consume(text: string): void {
    let offset = 0
    while (offset < text.length && !previewLimited) {
      const newline = text.indexOf('\n', offset)
      const end = newline === -1 ? text.length : newline
      // Retain one extra character so parseLogLine can mark a long line,
      // without accumulating an unbounded unterminated message.
      const room = MAX_LOG_LINE_CHARACTERS + 1 - pending.length
      if (room > 0) pending += text.slice(offset, Math.min(end, offset + room))
      if (newline === -1) break
      finishLine()
      offset = newline + 1
    }
  }

  try {
    while (!scanLimited && !previewLimited) {
      access.signal.throwIfAborted()
      const chunk = await reader.read()
      access.signal.throwIfAborted()
      if (chunk.done) {
        consume(decoder.decode())
        if (pending && !previewLimited) finishLine()
        break
      }
      for (let offset = 0; offset < chunk.value.byteLength && !previewLimited; offset += SCAN_CHUNK_BYTES) {
        access.signal.throwIfAborted()
        const end = Math.min(chunk.value.byteLength, offset + SCAN_CHUNK_BYTES,
          offset + MAX_RUNTIME_LOG_SCAN_BYTES - bytesRead)
        const bytes = chunk.value.subarray(offset, end)
        bytesRead += bytes.byteLength
        consume(decoder.decode(bytes, { stream: true }))
        if (bytesRead >= MAX_RUNTIME_LOG_SCAN_BYTES) {
          scanLimited = true
          break
        }
        if (bytesRead - lastPaintBytes >= PAINT_INTERVAL_BYTES) {
          access.onProgress?.(bytesRead)
          await new Promise<void>(resolve => setTimeout(resolve, 0))
          lastPaintBytes = bytesRead
        }
      }
    }
    access.signal.throwIfAborted()
    access.onProgress?.(bytesRead)
    return { content: lines.join('\n'), lineCount: lines.length, bytesRead,
      scanLimited, previewLimited, longLinesTruncated }
  } finally {
    access.signal.removeEventListener('abort', cancel)
    await reader.cancel().catch(() => undefined)
    reader.releaseLock()
  }
}
