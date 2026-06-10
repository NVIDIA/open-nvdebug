import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useThemeStore } from '@/stores/theme'

describe('theme store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  it('defaults to light theme', () => {
    const store = useThemeStore()
    expect(store.theme).toBe('light')
  })

  it('toggles theme', () => {
    const store = useThemeStore()
    store.toggle()
    expect(store.theme).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    store.toggle()
    expect(store.theme).toBe('light')
  })

  it('persists to localStorage', () => {
    const store = useThemeStore()
    store.setTheme('dark')
    expect(localStorage.getItem('nv-theme')).toBe('dark')
  })

  it('reads from localStorage on init', () => {
    localStorage.setItem('nv-theme', 'dark')
    const store = useThemeStore()
    expect(store.theme).toBe('dark')
  })
})
