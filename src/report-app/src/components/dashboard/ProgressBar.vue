<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

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
import {
  ACTIVE_COLLECTOR_STATUSES,
  TERMINAL_COLLECTOR_STATUSES,
  normalizeCollectorLifecycleCounts,
} from '@/utils/collectorLifecycle'

const props = withDefaults(defineProps<{
  counts: Record<string, number>
  excludeNotRan?: boolean
}>(), {
  excludeNotRan: false,
})

const statusToCss: Record<string, string> = {
  success: 'success',
  degraded: 'warning',
  error: 'error',
  partial: 'warning',
  skipped: 'skipped',
  cancelled: 'cancelled',
  running: 'running',
  pending: 'pending',
  not_ran: 'neutral',
}

const canonicalCounts = computed<Record<string, number>>(() => ({
  ...normalizeCollectorLifecycleCounts(props.counts),
  not_ran: props.counts.not_ran ?? 0,
}))

const segments = computed(() => {
  const order = [
    ...TERMINAL_COLLECTOR_STATUSES,
    ...ACTIVE_COLLECTOR_STATUSES,
    'not_ran',
  ]
  const filtered = props.excludeNotRan ? order.filter(s => s !== 'not_ran') : order
  const total = filtered.reduce(
    (sum, status) => sum + (canonicalCounts.value[status] || 0),
    0,
  )
  if (total === 0) return []

  return filtered
    .filter(status => (canonicalCounts.value[status] || 0) > 0)
    .map(status => ({
      status,
      cssStatus: statusToCss[status] || 'neutral',
      count: canonicalCounts.value[status] || 0,
      pct: ((canonicalCounts.value[status] || 0) / total) * 100,
      label: status.replace('_', ' '),
    }))
})
</script>
