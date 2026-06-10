<template>
  <div class="nv-progress nv-progress--lg">
    <div
      v-for="segment in segments"
      :key="segment.status"
      :class="['nv-progress__segment', `nv-progress__segment--${segment.cssStatus}`]"
      :style="{ width: segment.pct + '%' }"
      :title="`${segment.label}: ${segment.count}`"
    >
      <span v-if="segment.pct > 8" style="font-size: 0.6875rem; font-weight: 600; color: white; display: flex; align-items: center; justify-content: center; height: 100%;">{{ segment.count }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  counts: Record<string, number>
  excludeNotRan?: boolean
}>(), {
  excludeNotRan: false,
})

const statusToCss: Record<string, string> = {
  success: 'success',
  error: 'error',
  partial: 'warning',
  skipped: 'skipped',
  not_ran: 'neutral',
}

const segments = computed(() => {
  const order = ['success', 'error', 'partial', 'skipped', 'not_ran']
  const filtered = props.excludeNotRan ? order.filter(s => s !== 'not_ran') : order
  const total = filtered.reduce((sum, s) => sum + (props.counts[s] || 0), 0)
  if (total === 0) return []

  return filtered
    .filter(status => (props.counts[status] || 0) > 0)
    .map(status => ({
      status,
      cssStatus: statusToCss[status] || 'neutral',
      count: props.counts[status] || 0,
      pct: ((props.counts[status] || 0) / total) * 100,
      label: status.replace('_', ' '),
    }))
})
</script>
