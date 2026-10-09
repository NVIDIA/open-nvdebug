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

import { defineStore } from 'pinia'

export interface GrepResult {
  filePath: string
  lineNumber: number
  lineContent: string
  matchStart: number
  matchEnd: number
}

export const useSearchStore = defineStore('search', {
  state: () => ({
    grepQuery: '',
    grepRegex: false,
    grepScope: 'all' as 'all' | string, // 'all' or a DUT ID
    grepResults: [] as GrepResult[],
    grepSearching: false,
    grepFilesSearched: 0,
    grepFilesTotal: 0,
    grepPanelOpen: false,
  }),

  actions: {
    addResults(results: GrepResult[]) {
      this.grepResults.push(...results)
    },
    clearResults() {
      this.grepResults = []
      this.grepFilesSearched = 0
    },
    togglePanel() {
      this.grepPanelOpen = !this.grepPanelOpen
    },
  },
})
