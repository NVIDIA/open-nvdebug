import { defineStore } from 'pinia'

interface RouteFilters {
  [key: string]: string | number | boolean
}

export const useFilterStore = defineStore('filters', {
  state: () => ({
    perRoute: {} as Record<string, RouteFilters>,
  }),

  actions: {
    saveFilters(routeName: string, filters: RouteFilters) {
      this.perRoute[routeName] = { ...filters }
      try {
        sessionStorage.setItem('nv-filters', JSON.stringify(this.perRoute))
      } catch { /* quota exceeded */ }
    },

    loadFilters(routeName: string): RouteFilters {
      if (Object.keys(this.perRoute).length === 0) {
        try {
          const saved = sessionStorage.getItem('nv-filters')
          if (saved) this.perRoute = JSON.parse(saved)
        } catch { /* corrupt data */ }
      }
      return this.perRoute[routeName] ?? {}
    },

    clearFilters(routeName?: string) {
      if (routeName) {
        delete this.perRoute[routeName]
      } else {
        this.perRoute = {}
      }
      sessionStorage.removeItem('nv-filters')
    },
  },
})
