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
import { resolveServiceColor, useThemeColors } from '@/composables/useThemeColors'
import { toHex6 } from '@/utils/color'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const colors = useThemeColors()

const props = defineProps<{
  services: Array<{ service: string; total_duration: number }>
}>()

const hasData = computed(() => props.services.some(s => s.total_duration > 0))
const serviceColors = computed(() => props.services.map(s => toHex6(resolveServiceColor(s.service))))

const chartData = computed(() => ({
  labels: props.services.map(s => s.service),
  datasets: [{
    label: 'Total Time (s)',
    data: props.services.map(s => +s.total_duration.toFixed(1)),
    backgroundColor: serviceColors.value.map(color => color + 'b3'),
    hoverBackgroundColor: serviceColors.value,
    borderColor: serviceColors.value,
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
      callbacks: {
        label: (ctx: any) => ` ${ctx.raw}s`,
      },
    },
  },
  scales: {
    x: {
      title: { display: true, text: 'Seconds', color: colors.textTertiary, font: { size: colors.chartFontSize } },
      beginAtZero: true,
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
    y: {
      grid: { display: false },
      ticks: { color: colors.textSecondary, font: { size: colors.chartFontSize } },
    },
  },
}))
</script>

<style scoped>
.chart-container {
  height: 280px;
}
</style>
