<template>
  <div
    class="nv-skeleton"
    :style="{
      height: computedHeight,
      width: computedWidth,
      borderRadius: variant === 'card' ? 'var(--nv-radius-lg)' : undefined,
    }"
  />
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  variant?: 'card' | 'table-row' | 'chart' | 'text-block'
  width?: string
  height?: string
}>(), {
  variant: 'text-block',
})

const computedHeight = computed(() => {
  if (props.height) return props.height
  switch (props.variant) {
    case 'card': return '120px'
    case 'table-row': return '40px'
    case 'chart': return '300px'
    case 'text-block': return '16px'
    default: return '16px'
  }
})

const computedWidth = computed(() => props.width || '100%')
</script>
