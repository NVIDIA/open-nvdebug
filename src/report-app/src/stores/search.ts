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
