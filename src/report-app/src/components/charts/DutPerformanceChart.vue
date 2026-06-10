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
import EmptyState from '@/components/common/EmptyState.vue'
import { useThemeColors } from '@/composables/useThemeColors'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const colors = useThemeColors()

const props = defineProps<{
  duts: Array<{ id: string; duration: number; completed: number }>
}>()

const hasData = computed(() => props.duts.length > 0)

const chartData = computed(() => ({
  labels: props.duts.map(d => d.id),
  datasets: [
    {
      label: 'Duration (s)',
      data: props.duts.map(d => +d.duration.toFixed(1)),
      backgroundColor: colors.accent + 'b3',
      hoverBackgroundColor: colors.accent,
      borderColor: colors.accent,
      borderWidth: 1,
      yAxisID: 'y',
      borderRadius: 4,
    },
    {
      label: 'Collectors',
      data: props.duts.map(d => d.completed),
      backgroundColor: colors.chartBlue + 'b3',
      hoverBackgroundColor: colors.chartBlue,
      borderColor: colors.chartBlue,
      borderWidth: 1,
      yAxisID: 'y1',
      borderRadius: 4,
    },
  ],
}))

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: {
        color: colors.textSecondary,
        usePointStyle: true,
        pointStyleWidth: 8,
        font: { size: colors.chartFontSize },
        padding: 16,
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
    },
  },
  scales: {
    y: {
      type: 'linear' as const,
      position: 'left' as const,
      title: { display: true, text: 'Seconds', color: colors.textTertiary, font: { size: colors.chartFontSize } },
      beginAtZero: true,
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
    y1: {
      type: 'linear' as const,
      position: 'right' as const,
      title: { display: true, text: 'Collectors', color: colors.textTertiary, font: { size: colors.chartFontSize } },
      beginAtZero: true,
      grid: { drawOnChartArea: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
    x: {
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
  },
}))
</script>

<style scoped>
.chart-container {
  height: 280px;
}
</style>
