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
  timing: Record<string, number | null>
}>()

const hasData = computed(() =>
  Object.values(props.timing).some(v => v != null && v > 0)
)

const chartData = computed(() => {
  const entries = Object.entries(props.timing)
    .filter(([, v]) => v != null)
    .map(([k, v]) => ({ label: k.replace(/_/g, ' '), value: v as number }))
  return {
    labels: entries.map(e => e.label),
    datasets: [{
      label: 'Duration (s)',
      data: entries.map(e => +e.value.toFixed(2)),
      backgroundColor: colors.accent + 'b3',
      hoverBackgroundColor: colors.accent,
      borderColor: colors.accent,
      borderWidth: 1,
      borderRadius: 4,
    }],
  }
})

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
      callbacks: { label: (ctx: any) => ` ${ctx.raw}s` },
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
