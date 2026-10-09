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
 * Log analyzer worker — extracts levels, components, and timestamps from structured logs.
 *
 * Input: { content: string }
 * Output: { levels: string[], components: string[], lineCount: number, errorCount: number, warnCount: number }
 */

const LOG_PATTERN = /\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)/

export function handleMessage(data: { content: string }): {
  levels: string[]
  components: string[]
  lineCount: number
  errorCount: number
  warnCount: number
} {
  const levels = new Set<string>()
  const components = new Set<string>()
  let lineCount = 0
  let errorCount = 0
  let warnCount = 0

  const lines = data.content.split('\n')
  for (const line of lines) {
    lineCount++
    const match = line.match(LOG_PATTERN)
    if (match) {
      const level = match[2]
      const component = match[3]
      levels.add(level)
      components.add(component)
      if (level === 'ERROR') errorCount++
      if (level === 'WARNING') warnCount++
    }
  }

  return {
    levels: [...levels].sort(),
    components: [...components].sort(),
    lineCount,
    errorCount,
    warnCount,
  }
}

if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
