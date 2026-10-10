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
  <figure class="concurrency-chart-frame">
    <div
      class="concurrency-chart"
      :role="hasData ? 'img' : undefined"
      :aria-label="hasData ? accessibleSummary : undefined"
    >
      <Line v-if="hasData" :data="chartData" :options="chartOptions" aria-hidden="true" />
      <EmptyState
        v-else
        icon="data"
        title="Decision timeline unavailable"
        description="The scheduler artifact did not retain any valid decision points."
      />
    </div>
    <figcaption v-if="hasData" class="concurrency-chart__summary">{{ accessibleSummary }}</figcaption>
  </figure>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Line } from 'vue-chartjs'
import {
  Chart as ChartJS,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js'
import EmptyState from '@/components/common/EmptyState.vue'
import { useThemeColors } from '@/composables/useThemeColors'
import type { ConcurrencyDecisionPoint } from '@/types/concurrencyScheduler'

ChartJS.register(LinearScale, LineElement, PointElement, Tooltip, Legend)

const props = defineProps<{
  points: ConcurrencyDecisionPoint[]
  plannedOperations: number
}>()

const colors = useThemeColors()
const hasData = computed(() => props.points.length > 0)

function elapsedLabel(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`
  return `${(seconds / 3600).toFixed(2)}h`
}

const accessibleSummary = computed(() => {
  const capacities = props.points.map(point => point.newLimit)
  const finalPoint = props.points[props.points.length - 1]
  const completed = finalPoint?.cumulativeCompletedOperations ?? 0
  const progress = props.points.flatMap(point => point.progress ? [point.progress] : [])
  const demandSummary = progress.length > 0
    ? `with ${Math.max(...progress.map(point => point.activeOperations))} active and ${Math.max(...progress.map(point => point.queuedOperations))} queued at sampled decision points.`
    : 'Active and queued operation snapshots are unavailable in this artifact.'
  const elapsed = finalPoint?.elapsedSeconds ?? 0
  return `Concurrency scheduler timeline. Capacity ranged from ${Math.min(...capacities)} to ${Math.max(...capacities)} weighted operations, ${demandSummary} ${completed} of ${props.plannedOperations} planned operations completed by ${elapsedLabel(elapsed)}.`
})

const actionColor = (action: ConcurrencyDecisionPoint['action']): string => {
  if (action === 'increase') return '#76b900'
  if (action === 'decrease') return '#ef5350'
  if (action === 'start' || action === 'stop') return '#8c7cff'
  return '#f5a623'
}

const chartData = computed(() => ({
  datasets: [
    {
      label: 'Weighted capacity',
      data: props.points.map(point => ({ x: point.elapsedSeconds, y: point.newLimit })),
      yAxisID: 'capacity',
      borderColor: '#76b900',
      backgroundColor: '#76b90033',
      pointBackgroundColor: props.points.map(point => actionColor(point.action)),
      borderWidth: 2,
      pointRadius: 3,
      pointHoverRadius: 5,
      stepped: 'after' as const,
      tension: 0,
    },
    {
      label: 'Active operations',
      data: props.points.map(point => ({ x: point.elapsedSeconds, y: point.progress?.activeOperations ?? null })),
      yAxisID: 'capacity',
      borderColor: '#f5a623',
      backgroundColor: '#f5a62322',
      borderWidth: 1.5,
      pointRadius: 2,
      pointHoverRadius: 4,
      tension: 0.12,
      spanGaps: false,
    },
    {
      label: 'Queued operations',
      data: props.points.map(point => ({ x: point.elapsedSeconds, y: point.progress?.queuedOperations ?? null })),
      yAxisID: 'capacity',
      borderColor: '#ef5350',
      backgroundColor: '#ef535022',
      borderWidth: 1.5,
      pointRadius: 2,
      pointHoverRadius: 4,
      tension: 0.12,
      spanGaps: false,
    },
    {
      label: 'Completed operations',
      data: props.points.map(point => ({ x: point.elapsedSeconds, y: point.cumulativeCompletedOperations })),
      yAxisID: 'operations',
      borderColor: '#2ca8ff',
      backgroundColor: '#2ca8ff22',
      borderWidth: 1.5,
      pointRadius: 2,
      pointHoverRadius: 4,
      tension: 0.12,
    },
  ],
}))

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  animation: false as const,
  interaction: { mode: 'index' as const, intersect: false },
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: {
        color: colors.textSecondary,
        usePointStyle: true,
        pointStyleWidth: 8,
        font: { size: colors.chartFontSize },
        padding: 14,
      },
    },
    tooltip: {
      backgroundColor: colors.bgElevated || 'rgba(0, 0, 0, 0.88)',
      titleColor: colors.textPrimary,
      bodyColor: colors.textSecondary,
      borderColor: colors.border,
      borderWidth: 1,
      callbacks: {
        title: (items: Array<{ dataIndex: number; parsed: { x: number | null } }>) => {
          if (items.length === 0 || items[0].parsed.x === null) return 'Elapsed time unavailable'
          const point = props.points[items[0].dataIndex]
          return `Elapsed ${elapsedLabel(items[0].parsed.x)} · ${point.action}`
        },
        afterBody: (items: Array<{ dataIndex: number }>) => {
          if (items.length === 0) return []
          const point = props.points[items[0].dataIndex]
          return point.reasons.length > 0 ? [`Reason: ${point.reasons.join(', ')}`] : []
        },
      },
    },
  },
  scales: {
    x: {
      type: 'linear' as const,
      title: { display: true, text: 'Elapsed time', color: colors.textTertiary },
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, callback: (value: string | number) => elapsedLabel(Number(value)) },
    },
    capacity: {
      beginAtZero: true,
      position: 'left' as const,
      title: { display: true, text: 'Capacity / operation count', color: colors.textTertiary },
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, precision: 0 },
    },
    operations: {
      beginAtZero: true,
      suggestedMax: props.plannedOperations,
      position: 'right' as const,
      title: { display: true, text: 'Completed operations', color: colors.textTertiary },
      grid: { drawOnChartArea: false, drawBorder: false },
      ticks: { color: colors.textTertiary, precision: 0 },
    },
  },
}))
</script>

<style scoped>
.concurrency-chart-frame { margin: 0; }
.concurrency-chart { height: 320px; }
.concurrency-chart__summary {
  margin-top: 8px;
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
  line-height: 1.45;
}
</style>
