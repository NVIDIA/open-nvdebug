<template>
  <div :class="['nv-collapse', { 'nv-collapse--open': isOpen }]">
    <div
      class="nv-collapse__header"
      role="button"
      :aria-expanded="isOpen"
      tabindex="0"
      @click="toggle"
      @keydown.enter.prevent="toggle"
      @keydown.space.prevent="toggle"
    >
      <span v-if="number != null" class="nv-collapse__num">{{ number }}</span>
      <span class="nv-collapse__title">{{ title }}</span>
      <span v-if="badge" class="nv-collapse__badge">{{ badge }}</span>
      <span class="nv-collapse__toggle" aria-hidden="true">&#9662;</span>
    </div>
    <div v-if="isOpen" class="nv-collapse__body">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  number?: string | number
  title: string
  badge?: string
  collapsed?: boolean
}>(), {
  collapsed: false,
})

const emit = defineEmits<{
  'update:collapsed': [value: boolean]
}>()

const isOpen = computed(() => !props.collapsed)

function toggle() {
  emit('update:collapsed', !props.collapsed)
}
</script>
