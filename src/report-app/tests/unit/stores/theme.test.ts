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
