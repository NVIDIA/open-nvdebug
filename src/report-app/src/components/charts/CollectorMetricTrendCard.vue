<template>
  <div class="collector-metric nv-glass">
    <div class="collector-metric__header">
      <h4>{{ title }}</h4>
      <button
        v-if="selectedItem"
        class="collector-metric__reset"
        type="button"
        @click="selectedKey = ''"
      >
        Reset zoom
      </button>
    </div>

    <div v-if="selectedItem" class="collector-metric__zoom-note">
      Zoomed to {{ selectedItem.index }}. {{ selectedItem.group }} / {{ selectedItem.name }}
    </div>

    <div v-if="hasData" class="collector-metric__chart">
      <Line :data="chartData" :options="chartOptions" />
    </div>
    <EmptyState v-else icon="data" title="No collector data available" />

    <div v-if="topItems.length > 0" class="collector-metric__top">
      <div class="collector-metric__top-header">
        <h5>{{ topTitle }}</h5>
        <span>Top {{ topItems.length }}</span>
      </div>

      <div class="collector-metric__list">
        <button
          v-for="item in topItems"
          :key="`${item.dutId}:${item.id}:${item.index}`"
          :class="['collector-metric__item', { 'collector-metric__item--selected': selectedKey === itemKey(item) }]"
          type="button"
          @click="selectedKey = itemKey(item)"
        >
          <div class="collector-metric__item-main">
            <strong>{{ item.index }}. {{ item.group }} / {{ item.name }}</strong>
            <span>{{ item.dutId }} / {{ item.group }}</span>
          </div>
          <strong class="collector-metric__value">{{ formatValue(item.value) }}</strong>
          <div class="collector-metric__bar">
            <span :style="{ width: valuePercent(item.value) + '%' }" />
          </div>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { Line } from 'vue-chartjs'
import {
  Chart as ChartJS,
  type ChartData,
  type ChartOptions,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from 'chart.js'
import EmptyState from '@/components/common/EmptyState.vue'
import { useThemeColors } from '@/composables/useThemeColors'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)

export interface CollectorMetricItem {
  index: number
  id: string
  name: string
  group: string
  dutId: string
  value: number
}

const props = withDefaults(defineProps<{
  title: string
  yAxisTitle: string
  topTitle: string
  unitLabel: string
  items: CollectorMetricItem[]
  formatValue: (value: number) => string
  topLimit?: number
}>(), {
  topLimit: 5,
})

const colors = useThemeColors()
const accent = computed(() => colors.accent || '#76b900')
const chartBlue = computed(() => colors.chartBlue || '#6ea8fe')
const textSecondary = computed(() => colors.textSecondary || '#c6c6c6')
const textTertiary = computed(() => colors.textTertiary || '#8f8f8f')
const gridColor = computed(() => colors.gridColor || 'rgba(255,255,255,0.12)')
const selectedKey = ref('')
const ZOOM_RADIUS = 6

const metricItems = computed(() => [...props.items].filter(item => item.value >= 0))
const hasData = computed(() => metricItems.value.some(item => item.value > 0))
const topItems = computed(() => {
  return [...metricItems.value].filter(item => item.value > 0).sort((a, b) => b.value - a.value).slice(0, props.topLimit)
})
const topKeys = computed(() => new Set(topItems.value.map(item => itemKey(item))))
const maxValue = computed(() => Math.max(...metricItems.value.map(item => item.value), 0))
const selectedItem = computed(() => metricItems.value.find(item => itemKey(item) === selectedKey.value))
const visibleItems = computed(() => {
  if (!selectedItem.value) return metricItems.value
  const center = selectedItem.value.index
  return metricItems.value.filter(item => Math.abs(item.index - center) <= ZOOM_RADIUS)
})

const chartData = computed<ChartData<'line'>>(() => ({
  labels: visibleItems.value.map(item => String(item.index)),
  datasets: [{
    label: props.unitLabel,
    data: visibleItems.value.map(item => item.value),
    borderColor: chartBlue.value,
    backgroundColor: 'rgba(77,171,247,0.12)',
    fill: false,
    pointBackgroundColor: visibleItems.value.map(pointColor),
    pointBorderColor: visibleItems.value.map(pointColor),
    pointRadius: visibleItems.value.map(pointRadius),
    pointHoverRadius: 8,
    pointHitRadius: 12,
    pointBorderWidth: visibleItems.value.map(item => itemKey(item) === selectedKey.value ? 3 : 2),
    hoverBorderWidth: 3,
    borderWidth: 2,
    tension: 0.3,
    spanGaps: true,
    clip: false,
  }],
}))

const chartOptions = computed<ChartOptions<'line'>>(() => ({
  responsive: true,
  maintainAspectRatio: false,
  layout: { padding: { left: 12, right: 16, top: 8 } },
  interaction: {
    mode: 'nearest',
    intersect: false,
    axis: 'x',
  },
  hover: {
    mode: 'nearest',
    intersect: false,
  },
  plugins: {
    legend: { display: false },
    tooltip: {
      enabled: true,
      displayColors: false,
      backgroundColor: 'rgba(18,18,18,0.96)',
      titleColor: '#fff',
      bodyColor: 'rgba(255,255,255,0.85)',
      borderColor: 'rgba(118,185,0,0.35)',
      borderWidth: 1,
      cornerRadius: 8,
      caretPadding: 8,
      padding: 12,
      callbacks: {
        title: (items: any[]) => {
          const point = visibleItems.value[items?.[0]?.dataIndex]
          return point ? `${point.index}. ${point.group} / ${point.name}` : ''
        },
        label: (ctx: any) => ` ${props.formatValue(Number(ctx.raw) || 0)}`,
      },
    },
  },
  scales: {
    x: {
      title: { display: true, text: 'Collector number', color: textSecondary.value, font: { size: colors.chartFontSize || 12, weight: 'bold' } },
      grid: { display: false },
      ticks: {
        color: textTertiary.value,
        font: { size: colors.chartFontSize || 12 },
        maxRotation: 0,
        autoSkip: true,
        maxTicksLimit: 12,
      },
    },
    y: {
      title: { display: true, text: props.yAxisTitle, color: textSecondary.value, font: { size: colors.chartFontSize || 12, weight: 'bold' } },
      beginAtZero: true,
      grid: { color: gridColor.value, drawBorder: false },
      ticks: {
        color: textTertiary.value,
        font: { size: colors.chartFontSize || 12 },
        callback: (value: string | number) => props.formatValue(Number(value)),
      },
    },
  },
}))

function itemKey(item: CollectorMetricItem): string {
  return `${item.dutId}:${item.id}:${item.index}`
}

function pointColor(item: CollectorMetricItem): string {
  if (itemKey(item) === selectedKey.value) return accent.value
  if (topKeys.value.has(itemKey(item))) return accent.value
  return chartBlue.value
}

function pointRadius(item: CollectorMetricItem): number {
  if (itemKey(item) === selectedKey.value) return 7
  if (topKeys.value.has(itemKey(item))) return 4
  return 3
}

function valuePercent(value: number): number {
  if (maxValue.value <= 0) return 0
  return Math.max(2, Math.min(100, (value / maxValue.value) * 100))
}
</script>

<style scoped>
.collector-metric {
  overflow: hidden;
  border-color: var(--nv-glass-border-accent);
}

.collector-metric__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--nv-glass-border);
}

.collector-metric__header h4 {
  margin: 0;
  color: var(--nv-text-primary);
  font-size: 1rem;
  font-weight: 700;
}

.collector-metric__reset {
  border: 1px solid var(--nv-glass-border-highlight);
  border-radius: var(--nv-radius-sm);
  padding: 4px 8px;
  background: var(--nv-glass-bg-light);
  color: var(--nv-text-secondary);
  cursor: pointer;
  font-size: 0.6875rem;
  font-weight: 700;
  transition: var(--nv-transition-all);
}

.collector-metric__reset:hover,
.collector-metric__reset:focus-visible {
  border-color: var(--nv-accent);
  background: var(--nv-accent-muted);
  color: var(--nv-text-primary);
}

.collector-metric__zoom-note {
  margin: 12px 28px 0;
  padding: 8px 10px;
  border: 1px solid var(--nv-glass-border-accent);
  border-radius: var(--nv-radius-md);
  background: var(--nv-accent-subtle);
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
}

.collector-metric__chart {
  height: 340px;
  padding: 24px 28px 12px;
}

.collector-metric__top {
  margin: 16px 28px 28px;
  padding: 16px;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-lg);
  background: var(--nv-glass-bg-light);
}

.collector-metric__top-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}

.collector-metric__top-header h5 {
  margin: 0;
  color: var(--nv-text-primary);
  font-size: 0.875rem;
  font-weight: 700;
}

.collector-metric__top-header span {
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
  font-weight: 600;
}

.collector-metric__list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.collector-metric__item {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px 16px;
  width: 100%;
  border: 1px solid transparent;
  border-radius: var(--nv-radius-md);
  padding: 8px;
  background: transparent;
  text-align: left;
  cursor: pointer;
  transition: var(--nv-transition-all);
}

.collector-metric__item:hover,
.collector-metric__item:focus-visible {
  border-color: var(--nv-glass-border-highlight);
  background: color-mix(in srgb, var(--nv-bg-elevated) 68%, transparent);
  box-shadow: inset 3px 0 0 var(--nv-accent);
  transform: translateX(2px);
}

.collector-metric__item--selected {
  border-color: var(--nv-glass-border-accent);
  background: var(--nv-accent-subtle);
  box-shadow: inset 3px 0 0 var(--nv-accent), 0 8px 24px rgba(0, 0, 0, 0.18);
}

.collector-metric__item-main {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 2px;
}

.collector-metric__item-main strong {
  overflow: hidden;
  color: var(--nv-text-primary);
  font-size: 0.875rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.collector-metric__item-main span {
  overflow: hidden;
  color: var(--nv-text-tertiary);
  font-size: 0.75rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.collector-metric__value {
  color: var(--nv-text-secondary);
  font-family: var(--nv-font-mono);
  font-size: 0.875rem;
  font-weight: 600;
}

.collector-metric__bar {
  grid-column: 1 / -1;
  height: 8px;
  overflow: hidden;
  border-radius: var(--nv-radius-full);
  background: var(--nv-bg-tertiary);
}

.collector-metric__bar span {
  display: block;
  height: 100%;
  min-width: 2px;
  border-radius: inherit;
  background: #4dabf7;
}
</style>
