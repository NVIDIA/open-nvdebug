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

/**
 * Search index worker — searches file content for a pattern.
 *
 * Input: { content: string, query: string, filePath: string, regex?: boolean }
 * Output: { results: Array<{ filePath: string, lineNumber: number, lineContent: string, matchStart: number, matchEnd: number }> }
 */

import { compileSearchRegex } from '@/utils/searchRegex'

export function handleMessage(data: {
  content: string
  query: string
  filePath: string
  regex?: boolean
}): {
  results: Array<{
    filePath: string
    lineNumber: number
    lineContent: string
    matchStart: number
    matchEnd: number
  }>
} {
  const { content, query, filePath, regex } = data
  const results: Array<{
    filePath: string
    lineNumber: number
    lineContent: string
    matchStart: number
    matchEnd: number
  }> = []

  const lines = content.split('\n')
  const pattern = regex ? compileSearchRegex(query) : null

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (regex && pattern) {
      pattern.lastIndex = 0
      const match = pattern.exec(line)
      if (match) {
        results.push({
          filePath,
          lineNumber: i + 1,
          lineContent: line.slice(0, 200),
          matchStart: match.index,
          matchEnd: match.index + match[0].length,
        })
      }
    } else {
      const idx = line.toLowerCase().indexOf(query.toLowerCase())
      if (idx >= 0) {
        results.push({
          filePath,
          lineNumber: i + 1,
          lineContent: line.slice(0, 200),
          matchStart: idx,
          matchEnd: idx + query.length,
        })
      }
    }
  }

  return { results }
}

if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
