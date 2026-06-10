<template>
  <span :class="['nv-badge', badgeClass]">
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  status: string
}>()

const STATUS_ALIASES: Record<string, string> = {
  complete: 'success',
  passed: 'success',
  failed: 'error',
  notran: 'not_ran',
}

const normalizedStatus = computed(() => {
  const s = props.status?.toLowerCase() ?? 'unknown'
  return STATUS_ALIASES[s] ?? s
})

const label = computed(() => {
  const labels: Record<string, string> = {
    success: 'Success',
    error: 'Error',
    partial: 'Partial',
    skipped: 'Skipped',
    not_ran: 'Not Ran',
    unknown: 'Unknown',
    pass: 'Pass',
    fail: 'Fail',
    warning: 'Warning',
    skip: 'Skip',
    na: 'N/A',
    complete: 'Success',
  }
  return labels[props.status] || labels[normalizedStatus.value] || props.status
})

const badgeClass = computed(() => `nv-badge--${normalizedStatus.value}`)
</script>
