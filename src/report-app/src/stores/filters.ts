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
