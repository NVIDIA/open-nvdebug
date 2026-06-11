import { defineStore } from 'pinia'

export type ThemeMode = 'light' | 'dark'
export type FontSize = 'sm' | 'md' | 'lg'

const FONT_SIZE_MAP: Record<FontSize, string> = { sm: '14px', md: '15px', lg: '17px' }

export const useThemeStore = defineStore('theme', {
  state: () => ({
    theme: getInitialTheme(),
    fontSize: getInitialFontSize(),
  }),

  actions: {
    toggle() {
      this.theme = this.theme === 'light' ? 'dark' : 'light'
      this.apply()
    },

    setTheme(theme: ThemeMode) {
      this.theme = theme
      this.apply()
    },

    cycleFontSize() {
      const order: FontSize[] = ['sm', 'md', 'lg']
      const idx = order.indexOf(this.fontSize)
      this.fontSize = order[(idx + 1) % order.length]
      this.apply()
    },

    setFontSize(size: FontSize) {
      this.fontSize = size
      this.apply()
    },

    apply() {
      document.documentElement.setAttribute('data-theme', this.theme)
      document.documentElement.style.fontSize = FONT_SIZE_MAP[this.fontSize]
      localStorage.setItem('nv-theme', this.theme)
      localStorage.setItem('nv-font-size', this.fontSize)
    },

    init() {
      this.apply()
    },
  },
})

function getInitialFontSize(): FontSize {
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem('nv-font-size')
    if (saved === 'sm' || saved === 'md' || saved === 'lg') return saved
  }
  return 'md'
}

function getInitialTheme(): ThemeMode {
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem('nv-theme')
    if (saved === 'light' || saved === 'dark') return saved
  }
  if (typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches) {
    return 'dark'
  }
  return 'light'
}
