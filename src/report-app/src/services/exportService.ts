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
 * Client-side export utilities — generates Blobs for download.
 */

import { serializeCsv } from '@/utils/csv'

export function downloadCsv(
  rows: readonly (readonly unknown[])[],
  filename = 'export.csv',
): void {
  downloadBlob(
    serializeCsv(rows),
    filename,
    'text/csv;charset=utf-8',
  )
}

export function exportCsv(columns: string[], rows: Record<string, any>[]): void {
  downloadCsv([
    columns,
    ...rows.map(row => columns.map(column => row[column])),
  ])
}

export function exportJson(data: any, filename = 'export.json'): void {
  downloadBlob(JSON.stringify(data, null, 2), filename, 'application/json')
}

export function exportText(text: string, filename = 'export.txt'): void {
  downloadBlob(text, filename, 'text/plain')
}

export function exportManifest(manifest: any): void {
  exportJson(manifest, 'manifest.json')
}

function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
