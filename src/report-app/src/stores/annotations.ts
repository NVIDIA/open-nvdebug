import { defineStore } from 'pinia'

export interface Annotation {
  id: string
  itemPath: string    // route path or file path identifying what's annotated
  itemLabel: string   // display label
  text: string
  createdAt: string
}

export const useAnnotationsStore = defineStore('annotations', {
  state: () => ({
    annotations: [] as Annotation[],
    favorites: [] as string[],  // item paths
    reportKey: '',               // scoped by manifest.generated_at
  }),

  getters: {
    getAnnotation: (state) => (itemPath: string): Annotation | undefined =>
      state.annotations.find(a => a.itemPath === itemPath),

    hasAnnotation: (state) => (itemPath: string): boolean =>
      state.annotations.some(a => a.itemPath === itemPath),

    isFavorite: (state) => (itemPath: string): boolean =>
      state.favorites.includes(itemPath),
  },

  actions: {
    init(reportKey: string) {
      this.reportKey = reportKey
      this._load()
    },

    addAnnotation(itemPath: string, itemLabel: string, text: string) {
      const existing = this.annotations.findIndex(a => a.itemPath === itemPath)
      const annotation: Annotation = {
        id: Date.now().toString(36),
        itemPath,
        itemLabel,
        text,
        createdAt: new Date().toISOString(),
      }
      if (existing >= 0) {
        this.annotations[existing] = annotation
      } else {
        this.annotations.push(annotation)
      }
      this._save()
    },

    removeAnnotation(itemPath: string) {
      this.annotations = this.annotations.filter(a => a.itemPath !== itemPath)
      this._save()
    },

    toggleFavorite(itemPath: string) {
      const idx = this.favorites.indexOf(itemPath)
      if (idx >= 0) {
        this.favorites.splice(idx, 1)
      } else {
        this.favorites.push(itemPath)
      }
      this._save()
    },

    exportJson(): string {
      return JSON.stringify({ annotations: this.annotations, favorites: this.favorites }, null, 2)
    },

    importJson(json: string) {
      try {
        const data = JSON.parse(json)
        if (data.annotations) this.annotations = data.annotations
        if (data.favorites) this.favorites = data.favorites
        this._save()
      } catch { /* ignore invalid */ }
    },

    _save() {
      if (!this.reportKey) return
      localStorage.setItem(`nv-annotations-${this.reportKey}`, JSON.stringify({
        annotations: this.annotations,
        favorites: this.favorites,
      }))
    },

    _load() {
      if (!this.reportKey) return
      try {
        const raw = localStorage.getItem(`nv-annotations-${this.reportKey}`)
        if (raw) {
          const data = JSON.parse(raw)
          this.annotations = data.annotations ?? []
          this.favorites = data.favorites ?? []
        }
      } catch { /* ignore corrupt data */ }
    },
  },
})
