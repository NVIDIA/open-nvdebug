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

export const MAX_LOG_PREVIEW_CHARACTERS = 4 * 1024 * 1024
export const MAX_LOG_PREVIEW_LINES = 5_000
export const MAX_LOG_LINE_CHARACTERS = 16 * 1024

const LINE_TRUNCATION_LABEL = ' … [line truncated]'

export interface ParsedLogLine {
  raw: string
  timestamp: string | null
  level: string | null
  component: string | null
  collectorId: string | null
  message: string
  truncated: boolean
}

export interface LogPreview {
  lines: ParsedLogLine[]
  inspectedCharacters: number
  storedCharacters: number
  omittedCharacters: number
  truncatedLineCount: number
  lineLimitReached: boolean
  truncated: boolean
}

function isInlineWhitespace(character: string): boolean {
  const code = character.charCodeAt(0)
  return code === 0x09 || code === 0x0b || code === 0x0c || code === 0x0d || code === 0x20
}

function skipRequiredWhitespace(value: string, start: number): number | null {
  if (start >= value.length || !isInlineWhitespace(value[start])) return null
  let cursor = start + 1
  while (cursor < value.length && isInlineWhitespace(value[cursor])) cursor++
  return cursor
}

/** Parse the timestamp - name - level - message format used by tool config defaults. */
function parseDashSeparatedLine(raw: string, truncated: boolean): ParsedLogLine | null {
  const timestampEnd = raw.indexOf(' - ')
  if (timestampEnd < 0 || timestampEnd > 32) return null
  const timestamp = raw.slice(0, timestampEnd)
  if (!/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?$/.test(timestamp)) return null
  const componentEnd = raw.indexOf(' - ', timestampEnd + 3)
  if (componentEnd === -1) return null
  const levelEnd = raw.indexOf(' - ', componentEnd + 3)
  if (levelEnd === -1) return null
  const level = raw.slice(componentEnd + 3, levelEnd)
  if (!['DEBUG', 'INFO', 'WARNING', 'WARN', 'ERROR', 'CRITICAL', 'FATAL', 'TRACE'].includes(level)) return null

  let component = raw.slice(timestampEnd + 3, componentEnd)
  let collectorId: string | null = null
  if (component.startsWith('CID:')) {
    // The logger inserts "CID:<id>] [<component>" into the name field even
    // when the surrounding configured format does not use square brackets.
    const boundary = component.indexOf('] [', 4)
    if (boundary <= 4) return null
    collectorId = component.slice(4, boundary)
    component = component.slice(boundary + 3)
  }
  if (!component) return null
  return { raw, timestamp, level, component, collectorId,
    message: raw.slice(levelEnd + 3), truncated }
}

function parseBoundedLine(raw: string, truncated: boolean): ParsedLogLine {
  const fallback = (): ParsedLogLine => ({
    raw,
    timestamp: null,
    level: null,
    component: null,
    collectorId: null,
    message: raw,
    truncated,
  })

  if (raw[0] !== '[') return parseDashSeparatedLine(raw, truncated) ?? fallback()

  let cursor = 0
  const fields: string[] = []
  for (let fieldIndex = 0; fieldIndex < 3; fieldIndex++) {
    if (raw[cursor] !== '[') return fallback()
    const closingBracket = raw.indexOf(']', cursor + 1)
    if (closingBracket <= cursor + 1) return fallback()
    fields.push(raw.slice(cursor + 1, closingBracket))
    const next = skipRequiredWhitespace(raw, closingBracket + 1)
    if (next === null) return fallback()
    cursor = next
  }

  let collectorId: string | null = null
  let component = fields[2]
  if (component.startsWith('CID:')) {
    collectorId = component.slice(4)
    if (!collectorId || raw[cursor] !== '[') return fallback()
    const closingBracket = raw.indexOf(']', cursor + 1)
    if (closingBracket <= cursor + 1) return fallback()
    component = raw.slice(cursor + 1, closingBracket)
    const next = skipRequiredWhitespace(raw, closingBracket + 1)
    if (next === null) return fallback()
    cursor = next
  }

  return {
    raw,
    timestamp: fields[0],
    level: fields[1],
    component,
    collectorId,
    message: raw.slice(cursor),
    truncated,
  }
}

/** Parse one line with fixed input and retained-output bounds. */
export function parseLogLine(raw: string): ParsedLogLine {
  const truncated = raw.length > MAX_LOG_LINE_CHARACTERS
  const bounded = truncated
    ? raw.slice(0, MAX_LOG_LINE_CHARACTERS) + LINE_TRUNCATION_LABEL
    : raw
  return parseBoundedLine(bounded, truncated)
}

/**
 * Build a deterministic UI preview without scanning or retaining an unbounded
 * amount of attacker-controlled log content.
 */
export function parseLogPreview(content: string): LogPreview {
  const previewContent = content.length > MAX_LOG_PREVIEW_CHARACTERS
    ? content.slice(0, MAX_LOG_PREVIEW_CHARACTERS)
    : content
  const lines: ParsedLogLine[] = []
  let offset = 0
  let truncatedLineCount = 0
  let storedCharacters = 0

  while (offset <= previewContent.length && lines.length < MAX_LOG_PREVIEW_LINES) {
    const newline = previewContent.indexOf('\n', offset)
    const lineEnd = newline === -1 ? previewContent.length : newline
    const parsed = parseLogLine(previewContent.slice(offset, lineEnd))
    lines.push(parsed)
    if (parsed.truncated) truncatedLineCount++
    storedCharacters += parsed.raw.length

    if (newline === -1) {
      offset = previewContent.length
      break
    }
    offset = newline + 1
  }

  const lineLimitReached = lines.length === MAX_LOG_PREVIEW_LINES && offset < previewContent.length
  const inspectedCharacters = lineLimitReached ? offset : previewContent.length
  const omittedCharacters = Math.max(0, content.length - inspectedCharacters)
  const truncated = omittedCharacters > 0 || truncatedLineCount > 0

  return {
    lines,
    inspectedCharacters,
    storedCharacters,
    omittedCharacters,
    truncatedLineCount,
    lineLimitReached,
    truncated,
  }
}
