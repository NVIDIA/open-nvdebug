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
