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

import type { FileRef } from '@/types/manifest'

export type ViewerType = 'monaco' | 'log-viewer' | 'json-tree' | 'execution-summary' | 'download' | 'hex'

const STRUCTURED_LOG_FILES = new Set([
  'nvdebug_runtime_output.txt',
  'nvdebug_runtime_output_structured.txt',
])

export function getViewerType(file: FileRef): ViewerType {
  // Explicit hint from Python takes priority
  if (file.viewer_hint) return file.viewer_hint as ViewerType

  // Size gate: huge files → download only
  if (file.size > 200_000_000) return 'download'

  // Binary files
  if (file.type === 'binary') return 'download'

  // JSON → tree viewer
  if (file.type === 'json') return 'json-tree'

  if (file.path.split('/').pop() === 'Execution_Summary_Report.txt') {
    return 'execution-summary'
  }

  // Structured logs → log viewer
  if (isStructuredLog(file)) return 'log-viewer'

  // Everything else → Monaco
  return 'monaco'
}

function isStructuredLog(file: FileRef): boolean {
  const name = file.path.split('/').pop() ?? ''
  return STRUCTURED_LOG_FILES.has(name) || name.endsWith('_stdout.log')
}

/**
 * Detect if content is likely binary (has too many replacement characters).
 * If >5% of content is U+FFFD, it's probably binary.
 */
export function isBinaryContent(content: string): boolean {
  if (content.length === 0) return false
  const replacementCount = (content.match(/\uFFFD/g) || []).length
  return replacementCount / content.length > 0.05
}
