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

import { neutralizeSpreadsheetClipboardText } from '@/utils/csv'

/**
 * Copy text to clipboard with fallback for non-secure contexts (HTTP).
 * navigator.clipboard.writeText may exist but reject on HTTP — we catch
 * that and fall back to execCommand('copy').
 */
export async function copyToClipboard(text: string): Promise<void> {
  const safeText = neutralizeSpreadsheetClipboardText(text)
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(safeText)
      return
    } catch {
      // Clipboard API rejected (e.g. HTTP context) — fall through to fallback
    }
  }

  const textarea = document.createElement('textarea')
  textarea.value = safeText
  textarea.style.position = 'fixed'
  textarea.style.left = '-9999px'
  textarea.style.top = '-9999px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()
  try {
    document.execCommand('copy')
  } finally {
    document.body.removeChild(textarea)
  }
}
