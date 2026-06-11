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
  stages: { validation: number; execution: number; post_processing: number }
}>()

const hasData = computed(() =>
  props.stages.validation > 0 || props.stages.execution > 0 || props.stages.post_processing > 0
)

const chartData = computed(() => ({
  labels: ['Stages'],
  datasets: [
    {
      label: 'Validation',
      data: [props.stages.validation],
      backgroundColor: colors.chartBlue + 'b3',
      hoverBackgroundColor: colors.chartBlue,
      borderColor: colors.chartBlue,
      borderWidth: 1,
      borderRadius: 4,
    },
    {
      label: 'Execution',
      data: [props.stages.execution],
      backgroundColor: colors.accent + 'b3',
      hoverBackgroundColor: colors.accent,
      borderColor: colors.accent,
      borderWidth: 1,
      borderRadius: 4,
    },
    {
      label: 'Post-Processing',
      data: [props.stages.post_processing],
      backgroundColor: colors.chartPurple + 'b3',
      hoverBackgroundColor: colors.chartPurple,
      borderColor: colors.chartPurple,
      borderWidth: 1,
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
      callbacks: {
        label: (ctx: any) => ` ${ctx.dataset.label}: ${ctx.raw}s`,
      },
    },
  },
  scales: {
    x: {
      stacked: true,
      grid: { display: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
    y: {
      stacked: true,
      title: { display: true, text: 'Seconds', color: colors.textTertiary, font: { size: colors.chartFontSize } },
      beginAtZero: true,
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
