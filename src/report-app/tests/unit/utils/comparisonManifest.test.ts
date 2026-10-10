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

import { describe, expect, it, vi } from 'vitest'
import { MAX_MANIFEST_DOCUMENT_BYTES } from '@/stores/manifest'
import {
  extractLegacyEmbeddedManifest,
  parseComparisonManifestFile,
  parseComparisonReportFile,
} from '@/utils/comparisonManifest'

function comparisonFixture() {
  return {
    schema_version: '1.0',
    version: '1.0',
    generated_at: '2026-08-08T00:00:00Z',
    duts: null,
  }
}

describe('comparison manifest trust boundary', () => {
  it('rejects an oversized manifest before reading it', async () => {
    const text = vi.fn(async () => JSON.stringify(comparisonFixture()))

    await expect(parseComparisonManifestFile({
      size: MAX_MANIFEST_DOCUMENT_BYTES + 1,
      text,
    })).rejects.toThrow('exceeds the supported size limit')
    expect(text).not.toHaveBeenCalled()
  })

  it('routes standalone manifests through the primary normalizer', async () => {
    const source = JSON.stringify(comparisonFixture())
    const parsed = await parseComparisonManifestFile({
      size: new Blob([source]).size,
      text: async () => source,
    })

    expect(parsed.duts).toEqual([])
    expect(parsed.tool_version).toBe('unknown')
    expect(parsed.file_index).toEqual([])
  })

  it('extracts only a complete legacy assignment from a script element', () => {
    const source = `
      <script>const decoy = "window.__MANIFEST__ = {\\"generated_at\\":\\"wrong\\"}";</script>
      <script>window.__MANIFEST__ = ${JSON.stringify(comparisonFixture())};</script>
    `

    expect(extractLegacyEmbeddedManifest(source)).toEqual(comparisonFixture())
  })

  it('does not repeatedly rescan unterminated legacy assignments', () => {
    const source = `<script>${'window.__MANIFEST__={'.repeat(20_000)}</script>`

    expect(extractLegacyEmbeddedManifest(source)).toBeNull()
  })

  it('bounds and normalizes the legacy report fallback', async () => {
    const source = `<script>window.__MANIFEST__ = ${JSON.stringify(comparisonFixture())};</script>`
    const parsed = await parseComparisonReportFile({
      size: new Blob([source]).size,
      text: async () => source,
    })

    expect(parsed?.duts).toEqual([])
    expect(parsed?.collection_summary.run_result).toBeNull()
  })
})
