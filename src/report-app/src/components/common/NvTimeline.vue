<template>
  <div class="nv-timeline" role="list">
    <div
      v-for="(item, index) in items"
      :key="item.id ?? index"
      class="nv-timeline__event"
      role="listitem"
    >
      <span :class="['nv-timeline__dot', `nv-timeline__dot--${item.severity ?? 'neutral'}`]" />
      <div class="nv-timeline__header">
        <span v-if="item.time" class="nv-timeline__time">{{ item.time }}</span>
        <span v-if="item.source" class="nv-timeline__source">{{ item.source }}</span>
      </div>
      <div class="nv-timeline__desc">
        <slot :name="`event-${index}`" :item="item">
          {{ item.description }}
        </slot>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
export interface TimelineItem {
  id?: string | number
  time?: string
  source?: string
  description?: string
  severity?: 'success' | 'warning' | 'error' | 'info' | 'neutral'
}

defineProps<{
  items: TimelineItem[]
}>()
</script>
