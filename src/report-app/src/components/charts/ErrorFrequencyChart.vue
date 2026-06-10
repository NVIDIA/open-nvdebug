<template>
  <div class="chart-container">
    <Bar v-if="hasData" :data="chartData" :options="chartOptions" />
    <EmptyState v-else icon="data" title="No data available" />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js'
import type { ErrorEntry } from '@/types/manifest'
import EmptyState from '@/components/common/EmptyState.vue'
import { useThemeColors } from '@/composables/useThemeColors'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const colors = useThemeColors()

const props = defineProps<{
  errors: ErrorEntry[]
}>()

const hasData = computed(() => props.errors.length > 0)

const grouped = computed(() => {
  const map = new Map<string, number>()
  for (const e of props.errors) {
    const key = e.message.slice(0, 80)
    map.set(key, (map.get(key) ?? 0) + 1)
  }
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
})

const chartData = computed(() => ({
  labels: grouped.value.map(([msg]) => msg),
  datasets: [{
    label: 'Occurrences',
    data: grouped.value.map(([, count]) => count),
    backgroundColor: colors.error + 'b3',
    hoverBackgroundColor: colors.error,
    borderColor: colors.error,
    borderWidth: 1,
    borderRadius: 4,
  }],
}))

const chartOptions = computed(() => ({
  indexAxis: 'y' as const,
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: 'rgba(0,0,0,0.85)',
      titleColor: '#fff',
      bodyColor: 'rgba(255,255,255,0.85)',
      borderColor: 'rgba(255,255,255,0.1)',
      borderWidth: 1,
      cornerRadius: 6,
      padding: 10,
    },
  },
  scales: {
    x: {
      title: { display: true, text: 'Count', color: colors.textTertiary, font: { size: colors.chartFontSize } },
      beginAtZero: true,
      ticks: { stepSize: 1, color: colors.textTertiary, font: { size: colors.chartFontSize } },
      grid: { color: colors.gridColor, drawBorder: false },
    },
    y: {
      grid: { display: false },
      ticks: { color: colors.textSecondary, font: { size: colors.chartFontSizeSm } },
    },
  },
}))
</script>

<style scoped>
.chart-container {
  height: 280px;
}
</style>
