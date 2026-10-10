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

import { ref, computed, type Ref } from 'vue'

export interface VirtualScrollReturn<T> {
  visibleItems: Ref<Array<{ item: T; index: number }>>
  totalHeight: Ref<number>
  offsetY: Ref<number>
  onScroll: (e: Event) => void
}

/**
 * Lightweight virtual scroll for fixed-height items.
 * Renders only the items visible within the container plus a buffer.
 */
export function useVirtualScroll<T>(
  items: Ref<T[]>,
  containerHeight: Ref<number>,
  itemHeight: number,
  overscan = 10,
): VirtualScrollReturn<T> {
  const scrollTop = ref(0)

  const totalHeight = computed(() => items.value.length * itemHeight)

  const startIndex = computed(() =>
    Math.max(0, Math.floor(scrollTop.value / itemHeight) - overscan)
  )

  const endIndex = computed(() =>
    Math.min(
      items.value.length,
      Math.ceil((scrollTop.value + containerHeight.value) / itemHeight) + overscan,
    )
  )

  const offsetY = computed(() => startIndex.value * itemHeight)

  const visibleItems = computed(() =>
    items.value
      .slice(startIndex.value, endIndex.value)
      .map((item, i) => ({ item, index: startIndex.value + i }))
  )

  function onScroll(e: Event) {
    const el = e.target as HTMLElement
    scrollTop.value = el.scrollTop
  }

  return { visibleItems, totalHeight, offsetY, onScroll }
}
