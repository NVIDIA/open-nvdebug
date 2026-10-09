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
  <div class="chart-container">
    <Doughnut v-if="hasData" :data="chartData" :options="chartOptions" @click="onClick" ref="chartRef" />
    <EmptyState v-else icon="data" title="No data available" />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { Doughnut } from 'vue-chartjs'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'
import EmptyState from '@/components/common/EmptyState.vue'
import { useRouter } from 'vue-router'
import { resolveStatusColor, useThemeColors } from '@/composables/useThemeColors'
import { useThemeStore } from '@/stores/theme'
import {
  ACTIVE_COLLECTOR_STATUSES,
  TERMINAL_COLLECTOR_STATUSES,
  normalizeCollectorLifecycleCounts,
} from '@/utils/collectorLifecycle'

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps<{
  counts: Record<string, number>
}>()

const router = useRouter()
const chartRef = ref()
const themeStore = useThemeStore()
// Re-resolve CSS variables whenever the theme changes: a one-time snapshot
// leaves dark-theme borders painted on the light theme (and vice versa).
const colors = computed(() => {
  void themeStore.theme
  return useThemeColors()
})

const statusOrder = [
  ...TERMINAL_COLLECTOR_STATUSES,
  ...ACTIVE_COLLECTOR_STATUSES,
  'not_ran',
]

const canonicalCounts = computed<Record<string, number>>(() => ({
  ...normalizeCollectorLifecycleCounts(props.counts),
  not_ran: props.counts.not_ran ?? 0,
}))

const hasData = computed(() =>
  statusOrder.some(status => (canonicalCounts.value[status] ?? 0) > 0),
)

const chartData = computed(() => {
  const labels = statusOrder.filter(
    status => (canonicalCounts.value[status] ?? 0) > 0,
  )
  return {
    labels: labels.map(s => s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())),
    datasets: [{
      data: labels.map(s => canonicalCounts.value[s] ?? 0),
      backgroundColor: labels.map(s => resolveStatusColor(s) + 'b3'),
      hoverBackgroundColor: labels.map(s => resolveStatusColor(s)),
      borderWidth: 2,
      borderColor: colors.value.bgPrimary || '#1a1a1a',
      hoverBorderWidth: 3,
      hoverOffset: 6,
    }],
  }
})

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  cutout: '65%',
  animation: { animateRotate: true, animateScale: true },
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: {
        padding: 16,
        usePointStyle: true,
        pointStyleWidth: 8,
        color: colors.value.textSecondary,
        font: { size: colors.value.chartFontSize },
      },
    },
    tooltip: {
      backgroundColor: 'rgba(0,0,0,0.85)',
      titleColor: '#fff',
      bodyColor: 'rgba(255,255,255,0.85)',
      borderColor: 'rgba(255,255,255,0.1)',
      borderWidth: 1,
      cornerRadius: 6,
      padding: 10,
      callbacks: {
        label: (ctx: any) => {
          const total = ctx.dataset.data.reduce((a: number, b: number) => a + b, 0)
          const pct = ((ctx.raw / total) * 100).toFixed(1)
          return ` ${ctx.label}: ${ctx.raw} (${pct}%)`
        },
      },
    },
  },
}))

function onClick(event: any) {
  const chart = chartRef.value?.chart
  if (!chart) return
  const elements = chart.getElementsAtEventForMode(event, 'nearest', { intersect: true }, false)
  if (elements.length > 0) {
    const index = elements[0].index
    const labels = statusOrder.filter(
      status => (canonicalCounts.value[status] ?? 0) > 0,
    )
    const status = labels[index]
    if (status) router.push(`/status/${status}`)
  }
}
</script>

<style scoped>
.chart-container {
  height: 260px;
  max-width: 320px;
  margin: 0 auto;
}
</style>
