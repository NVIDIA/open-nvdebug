<template>
  <span :class="['nv-badge', badgeClass]">
    {{ label }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  service: string
}>()

const label = computed(() => {
  const labels: Record<string, string> = {
    redfish: 'Redfish',
    ssh: 'SSH',
    ipmi: 'IPMI',
    health_check: 'Health Check',
    host: 'Host',
    bmc: 'BMC',
    preflight: 'Preflight',
  }
  return labels[props.service] || props.service
})

const badgeClass = computed(() => `nv-badge--${props.service}`)
</script>
