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

/** Spreadsheet-safe CSV serialization for report data from untrusted devices. */

const FORMULA_PREFIX = /^[\p{White_Space}\p{Cc}\p{Cf}]*[=+\-@]/u
const CSV_QUOTING_REQUIRED = /[",\r\n]/

/**
 * Prevent spreadsheet applications from interpreting a cell as a formula.
 *
 * Importers can discard leading whitespace and control/format characters
 * before recognizing formula triggers. Prefixing the complete original value
 * with an apostrophe keeps the cell textual without discarding report data.
 */
export function neutralizeCsvFormula(value: string): string {
  return FORMULA_PREFIX.test(value) ? `'${value}` : value
}

/** Preserve raw delimiters while making every clipboard record/cell textual. */
export function neutralizeSpreadsheetClipboardText(value: unknown): string {
  if (value === null || value === undefined) return ''

  return String(value)
    .split(/(\r\n|\r|\n|\t)/)
    .map((part, index) => index % 2 === 0 ? neutralizeCsvFormula(part) : part)
    .join('')
}

/** Serialize one cell for tabular clipboard output without creating new cells. */
export function serializeTsvCell(value: unknown): string {
  if (value === null || value === undefined) return ''

  const text = String(value)
    .replace(/\\/g, '\\\\')
    .replace(/\t/g, '\\t')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
  return neutralizeCsvFormula(text)
}

/** Serialize one value as a comma-delimited CSV cell. */
export function serializeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return ''

  const text = neutralizeCsvFormula(String(value))
  if (!CSV_QUOTING_REQUIRED.test(text)) return text
  return `"${text.replace(/"/g, '""')}"`
}

/** Serialize rows using RFC 4180 record delimiters and field escaping. */
export function serializeCsv(rows: readonly (readonly unknown[])[]): string {
  return rows
    .map(row => row.map(serializeCsvCell).join(','))
    .join('\r\n')
}
