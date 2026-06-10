import { ref, watch } from 'vue'

const STORAGE_KEY = 'nv-viewer-prefs'

interface ViewerPrefs {
  wordWrap: boolean
  jsonRawMode: boolean
}

function load(): ViewerPrefs {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (raw) return { ...defaults(), ...JSON.parse(raw) }
  } catch { /* ignore */ }
  return defaults()
}

function defaults(): ViewerPrefs {
  return { wordWrap: true, jsonRawMode: false }
}

function persist(prefs: ViewerPrefs) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch { /* quota exceeded, ignore */ }
}

const stored = load()
export const wordWrap = ref(stored.wordWrap)
export const jsonRawMode = ref(stored.jsonRawMode)

watch([wordWrap, jsonRawMode], () => {
  persist({ wordWrap: wordWrap.value, jsonRawMode: jsonRawMode.value })
})
