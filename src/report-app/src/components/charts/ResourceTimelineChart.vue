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
  <figure class="resource-chart-frame">
    <div
      class="resource-chart"
      :role="hasData ? 'img' : undefined"
      :aria-label="hasData ? accessibleSummary : undefined"
    >
      <Line v-if="hasData" :data="chartData" :options="chartOptions" aria-hidden="true" />
      <EmptyState
        v-else
        icon="data"
        title="Metric unavailable"
        description="This run did not record any values for the selected metric."
      />
    </div>
    <figcaption v-if="hasData" class="resource-chart__summary">{{ accessibleSummary }}</figcaption>
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
import type { ResourceSamplePoint } from '@/types/resourceUsage'

ChartJS.register(LinearScale, LineElement, PointElement, Tooltip, Legend)

export interface ResourceTimelineSeries {
  key: keyof ResourceSamplePoint
  label: string
  color: string
}

const props = defineProps<{
  points: ResourceSamplePoint[]
  series: ResourceTimelineSeries[]
  yAxisTitle: string
  accessibilityLabel: string
  valueSuffix?: string
  divisor?: number
}>()

const colors = useThemeColors()

const hasData = computed(() => props.series.some(series =>
  props.points.some(point => (
    typeof point.elapsedSeconds === 'number'
    && Number.isFinite(point.elapsedSeconds)
    && typeof point[series.key] === 'number'
    && Number.isFinite(point[series.key])
  )),
))

const accessibleSummary = computed(() => {
  const summaries = props.series.flatMap(series => {
    const values = props.points
      .filter(point => typeof point.elapsedSeconds === 'number' && Number.isFinite(point.elapsedSeconds))
      .map(point => point[series.key])
      .filter((value): value is number => typeof value === 'number' && Number.isFinite(value))
      .map(value => value / (props.divisor ?? 1))
    if (values.length === 0) return []
    const minimum = Math.min(...values)
    const maximum = Math.max(...values)
    const suffix = props.valueSuffix ?? ''
    return [`${series.label}: minimum ${minimum.toFixed(2)}${suffix}, maximum ${maximum.toFixed(2)}${suffix}`]
  })
  const elapsed = props.points
    .map(point => point.elapsedSeconds)
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value))
  const range = elapsed.length > 0
    ? `Elapsed range ${elapsedLabel(Math.min(...elapsed))} to ${elapsedLabel(Math.max(...elapsed))}`
    : 'Elapsed range unavailable'
  return `${props.accessibilityLabel}. ${range}. ${summaries.join('; ')}.`
})

function elapsedLabel(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`
  return `${(seconds / 3600).toFixed(2)}h`
}

const chartData = computed(() => ({
  datasets: props.series.map(series => ({
    label: series.label,
    data: props.points.flatMap(point => {
      const value = point[series.key]
      if (point.elapsedSeconds === null || !Number.isFinite(point.elapsedSeconds)) return []
      return [{
        x: point.elapsedSeconds,
        y: typeof value === 'number' && Number.isFinite(value) ? value / (props.divisor ?? 1) : null,
      }]
    }),
    borderColor: series.color,
    backgroundColor: `${series.color}33`,
    borderWidth: 1.5,
    pointRadius: 0,
    pointHoverRadius: 3,
    spanGaps: false,
    tension: 0.12,
  })),
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
        title: (items: Array<{ parsed: { x: number | null } }>) => items.length > 0 && items[0].parsed.x !== null
          ? `Elapsed ${elapsedLabel(items[0].parsed.x)}`
          : 'Elapsed time unavailable',
        label: (context: { dataset: { label?: string }; parsed: { y: number | null } }) => {
          if (context.parsed.y === null) return `${context.dataset.label}: Unavailable`
          const value = Number.isInteger(context.parsed.y)
            ? String(context.parsed.y)
            : context.parsed.y.toFixed(2)
          return `${context.dataset.label}: ${value}${props.valueSuffix ?? ''}`
        },
      },
    },
  },
  scales: {
    x: {
      type: 'linear' as const,
      title: {
        display: true,
        text: 'Elapsed time',
        color: colors.textTertiary,
        font: { size: colors.chartFontSize },
      },
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: {
        color: colors.textTertiary,
        maxTicksLimit: 10,
        font: { size: colors.chartFontSize },
        callback: (value: string | number) => elapsedLabel(Number(value)),
      },
    },
    y: {
      beginAtZero: true,
      title: {
        display: true,
        text: props.yAxisTitle,
        color: colors.textTertiary,
        font: { size: colors.chartFontSize },
      },
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
  },
}))
</script>

<style scoped>
.resource-chart-frame { margin: 0; }
.resource-chart {
  height: 290px;
}
.resource-chart__summary {
  margin-top: 8px;
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
  line-height: 1.45;
}
</style>
