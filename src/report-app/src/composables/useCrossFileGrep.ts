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

import { useManifestStore } from '@/stores/manifest'
import { useSearchStore, type GrepResult } from '@/stores/search'
import { DataLoader } from '@/services/dataLoader'
import { useFileSystemStore } from '@/stores/fileSystem'
import { compileSearchRegex } from '@/utils/searchRegex'

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB

export function useCrossFileGrep() {
  const manifestStore = useManifestStore()
  const searchStore = useSearchStore()
  const fileSystemStore = useFileSystemStore()
  let aborted = false

  async function grep(query: string, options: { regex?: boolean; scope?: string } = {}) {
    aborted = false
    searchStore.clearResults()
    searchStore.grepSearching = true
    searchStore.grepQuery = query

    const loader = new DataLoader()
    if (fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded) {
      loader.setFileMap(fileSystemStore.fileMap)
    }

    // Filter files by scope and size
    let files = manifestStore.fileIndex.filter(f => f.size < MAX_FILE_SIZE && f.type !== 'binary')
    if (options.scope && options.scope !== 'all') {
      files = files.filter(f => f.dut_id === options.scope)
    }

    searchStore.grepFilesTotal = files.length

    for (const file of files) {
      if (aborted) break
      try {
        const content = await loader.loadFile(file)
        const results = searchInContent(content, query, file.path, options.regex)
        if (results.length > 0) {
          searchStore.addResults(results)
        }
      } catch {
        // Skip files that can't be loaded
      }
      searchStore.grepFilesSearched++
    }

    searchStore.grepSearching = false
  }

  function abort() {
    aborted = true
  }

  return { grep, abort }
}

function searchInContent(content: string, query: string, filePath: string, regex?: boolean): GrepResult[] {
  const results: GrepResult[] = []
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
  return results
}
