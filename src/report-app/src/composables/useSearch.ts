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

import { ref, watch } from 'vue'
import type { RouteLocationRaw } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import type { FileEntry, ErrorEntry } from '@/types/manifest'
import { collectorDetailRoute, dutRoute } from '@/utils/reportRoutes'

export interface SearchResult {
  type: 'file' | 'collector' | 'dut' | 'error'
  label: string
  sublabel: string
  path: RouteLocationRaw
  score: number
}

export function useSearch() {
  const manifestStore = useManifestStore()
  const query = ref('')
  const results = ref<SearchResult[]>([])

  function search(q: string): SearchResult[] {
    if (!q || q.length < 2) return []
    const lower = q.toLowerCase()
    const matched: SearchResult[] = []

    // Search files
    for (const f of manifestStore.fileIndex) {
      const fileName = f.path.split('/').pop() ?? ''
      const score = fuzzyScore(lower, f.path.toLowerCase())
      if (score > 0) {
        matched.push({
          type: 'file',
          label: fileName,
          sublabel: f.path,
          path: `/file/${encodeURIComponent(f.path)}`,
          score,
        })
      }
    }

    // Search DUTs
    for (const dut of manifestStore.duts) {
      if (dut.id.toLowerCase().includes(lower)) {
        matched.push({
          type: 'dut',
          label: dut.id,
          sublabel: `${dut.baseboard} — ${dut.overall_status}`,
          path: dutRoute(dut.id),
          score: 100,
        })
      }
    }

    // Search collectors
    for (const dut of manifestStore.duts) {
      for (const group of dut.collector_groups) {
        for (const c of group.collectors) {
          const text = `${c.id} ${c.name}`.toLowerCase()
          if (text.includes(lower)) {
            matched.push({
              type: 'collector',
              label: `${c.id} — ${c.name}`,
              sublabel: `${dut.id} / ${group.name}`,
              path: collectorDetailRoute(dut.id, group.name, c.id),
              score: 80,
            })
          }
        }
      }
    }

    // Search errors
    for (const e of manifestStore.errors) {
      if (e.message.toLowerCase().includes(lower)) {
        matched.push({
          type: 'error',
          label: e.message.slice(0, 80),
          sublabel: `${e.dut_id} / ${e.collector_id}`,
          path: collectorDetailRoute(e.dut_id, e.collector_group, e.collector_id),
          score: 60,
        })
      }
    }

    return matched.sort((a, b) => b.score - a.score).slice(0, 50)
  }

  // Simple fuzzy scoring
  function fuzzyScore(query: string, target: string): number {
    if (target.includes(query)) return 100 - target.indexOf(query)
    // Check if all chars appear in order
    let qi = 0
    for (let i = 0; i < target.length && qi < query.length; i++) {
      if (target[i] === query[qi]) qi++
    }
    return qi === query.length ? 50 - query.length : 0
  }

  let debounceTimer: ReturnType<typeof setTimeout>
  watch(query, (q) => {
    clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => {
      results.value = search(q)
    }, 50)
  })

  return { query, results, search }
}
