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
  MAX_MANIFEST_DOCUMENT_BYTES,
  validateAndNormalize,
} from '@/stores/manifest'
import type { Manifest } from '@/types/manifest'

type ComparisonFile = Pick<File, 'size' | 'text'>

function assertBounded(file: ComparisonFile, label: string): void {
  if (!Number.isSafeInteger(file.size) || file.size < 0) {
    throw new Error(`The selected ${label} has an invalid size`)
  }
  if (file.size > MAX_MANIFEST_DOCUMENT_BYTES) {
    throw new Error(`The selected ${label} exceeds the supported size limit`)
  }
}

export async function parseComparisonManifestFile(
  file: ComparisonFile,
): Promise<Manifest> {
  assertBounded(file, 'manifest.json')
  return validateAndNormalize(JSON.parse(await file.text()))
}

function jsonObjectEnd(source: string, start: number): number {
  let depth = 0
  let inString = false
  let escaped = false

  for (let index = start; index < source.length; index += 1) {
    const character = source[index]
    if (inString) {
      if (escaped) {
        escaped = false
      } else if (character === '\\') {
        escaped = true
      } else if (character === '"') {
        inString = false
      }
      continue
    }
    if (character === '"') {
      inString = true
    } else if (character === '{') {
      depth += 1
    } else if (character === '}') {
      depth -= 1
      if (depth === 0) return index
      if (depth < 0) return -1
    }
  }
  return -1
}

/** Extract the old window.__MANIFEST__ assignment without an unbounded HTML regex. */
export function extractLegacyEmbeddedManifest(source: string): unknown | null {
  const lowerSource = source.toLowerCase()
  const assignmentMarker = 'window.__MANIFEST__'
  let searchFrom = 0

  while (searchFrom < source.length) {
    const scriptStart = lowerSource.indexOf('<script', searchFrom)
    if (scriptStart < 0) return null
    const bodyStart = source.indexOf('>', scriptStart)
    if (bodyStart < 0) return null
    const scriptEnd = lowerSource.indexOf('</script>', bodyStart + 1)
    if (scriptEnd < 0) return null
    const body = source.slice(bodyStart + 1, scriptEnd)

    let markerStart = body.indexOf(assignmentMarker)
    while (markerStart >= 0) {
      let cursor = markerStart + assignmentMarker.length
      while (/\s/u.test(body[cursor] ?? '')) cursor += 1
      if (body[cursor] !== '=') {
        markerStart = body.indexOf(assignmentMarker, cursor)
        continue
      }
      cursor += 1
      while (/\s/u.test(body[cursor] ?? '')) cursor += 1
      if (body[cursor] !== '{') {
        markerStart = body.indexOf(assignmentMarker, cursor)
        continue
      }

      const objectEnd = jsonObjectEnd(body, cursor)
      if (objectEnd >= 0) {
        const remainder = body.slice(objectEnd + 1).trim()
        if (remainder === '' || remainder === ';') {
          return JSON.parse(body.slice(cursor, objectEnd + 1))
        }
        // The parsed object cannot be the standalone legacy assignment. Skip
        // its complete range so nested marker text is never scanned again.
        markerStart = body.indexOf(assignmentMarker, objectEnd + 1)
        continue
      }

      // An unterminated object consumes the remainder of this script block.
      // Looking for another marker inside it would rescan the same suffix for
      // every candidate and turn malformed input into quadratic work.
      break
    }
    searchFrom = scriptEnd + '</script>'.length
  }
  return null
}

export async function parseComparisonReportFile(
  file: ComparisonFile,
): Promise<Manifest | null> {
  assertBounded(file, 'report index.html')
  const embedded = extractLegacyEmbeddedManifest(await file.text())
  return embedded === null ? null : validateAndNormalize(embedded)
}
