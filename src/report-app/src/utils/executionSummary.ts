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

export interface ExecutionSummaryRow {
  collectionName: string
  collectorId: string
  status: string
  logPaths: string[]
  durationSeconds: string
  reason: string
  artifactPaths: string[]
  diagnosticPaths: string[]
  failureCategory: string
}

export interface ExecutionSummaryDocument {
  valid: boolean
  rows: ExecutionSummaryRow[]
  totalExecutionTime: string
  error?: string
}

const REQUIRED_HEADERS = ['collection name', 'execution status']
const MAX_STRUCTURED_SUMMARY_CHARS = 8 * 1024 * 1024
const MAX_STRUCTURED_SUMMARY_ROWS = 1_000

function normalizedHeader(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ')
}

function splitPaths(value: string): string[] {
  return value.split(',').map(path => path.trim()).filter(Boolean)
}

export function parseExecutionSummary(content: string): ExecutionSummaryDocument {
  if (content.length > MAX_STRUCTURED_SUMMARY_CHARS) {
    return { valid: false, rows: [], totalExecutionTime: '', error: 'Execution summary is too large for structured display.' }
  }
  const lines = content.split(/\r?\n/)
  const headerIndex = lines.findIndex(line => line.trim())
  if (headerIndex < 0) {
    return { valid: false, rows: [], totalExecutionTime: '', error: 'Execution summary is empty.' }
  }

  const headerLine = lines[headerIndex]
  if (!headerLine.includes('\t')) {
    return { valid: false, rows: [], totalExecutionTime: '', error: 'Execution summary is not tab-separated.' }
  }

  const headers = headerLine.split('\t').map(normalizedHeader)
  if (REQUIRED_HEADERS.some(header => !headers.includes(header))) {
    return { valid: false, rows: [], totalExecutionTime: '', error: 'Execution summary is missing required columns.' }
  }

  const indexOf = (name: string) => headers.indexOf(name)
  const at = (cells: string[], index: number) => index >= 0 ? (cells[index] ?? '').trim() : ''
  const rows: ExecutionSummaryRow[] = []
  let totalExecutionTime = ''

  for (const rawLine of lines.slice(headerIndex + 1)) {
    const line = rawLine.trim()
    if (!line) continue
    if (!rawLine.includes('\t')) {
      if (/^(?:total execution time:|log collection took\b)/i.test(line)) {
        totalExecutionTime = line
        continue
      }
      return { valid: false, rows: [], totalExecutionTime, error: 'Execution summary contains a malformed row.' }
    }

    const cells = rawLine.split('\t')
    if (cells.length < headers.length) {
      cells.push(...Array(headers.length - cells.length).fill(''))
    }
    rows.push({
      collectionName: at(cells, indexOf('collection name')),
      collectorId: at(cells, indexOf('id')) || at(cells, indexOf('collector id')),
      status: at(cells, indexOf('execution status')),
      logPaths: splitPaths(at(cells, indexOf('log path'))),
      durationSeconds: at(cells, indexOf('duration (s)')) || at(cells, indexOf('duration')),
      reason: at(cells, indexOf('reason')),
      artifactPaths: splitPaths(at(cells, indexOf('artifact paths'))),
      diagnosticPaths: splitPaths(at(cells, indexOf('diagnostic paths'))),
      failureCategory: at(cells, indexOf('failure category')),
    })
    if (rows.length > MAX_STRUCTURED_SUMMARY_ROWS) {
      return { valid: false, rows: [], totalExecutionTime, error: 'Execution summary has too many rows for structured display.' }
    }
  }

  return { valid: true, rows, totalExecutionTime }
}
