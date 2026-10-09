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
 * File parser worker — extracts line boundaries from large text content.
 * Used for virtual viewport rendering of large files.
 *
 * Input: { content: string, chunkSize?: number }
 * Output: { lineCount: number, lineOffsets: number[], complete: boolean }
 */

export function handleMessage(data: { content: string; chunkSize?: number }): {
  lineCount: number
  lineOffsets: number[]
  complete: boolean
} {
  const { content, chunkSize = 50000 } = data
  const lineOffsets: number[] = [0]

  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') {
      lineOffsets.push(i + 1)
    }
  }

  return {
    lineCount: lineOffsets.length,
    lineOffsets,
    complete: true,
  }
}

// Worker entry point (runs when loaded as a Blob URL worker)
if (typeof self !== 'undefined' && typeof (self as any).onmessage !== 'undefined') {
  self.onmessage = (event: MessageEvent) => {
    const result = handleMessage(event.data)
    self.postMessage(result)
  }
}
