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
import type { DUT } from '@/types/manifest'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const props = defineProps<{
  duts: DUT[]
}>()

const colors = useThemeColors()

const hasData = computed(() => props.duts.length > 0)

const chartData = computed(() => {
  const labels = props.duts.map(d => d.id)
  const allGroups = [...new Set(props.duts.flatMap(d => d.collector_groups.map(g => g.name)))].sort()

  const datasets = allGroups.map(group => {
    const base = resolveServiceColor(group)
    return {
      label: group,
      data: props.duts.map(dut => {
        const g = dut.collector_groups.find(cg => cg.name === group)
        return g ? +(g.total_execution_time / 60).toFixed(2) : 0
      }),
      backgroundColor: base + 'b3',
      hoverBackgroundColor: base,
      borderColor: base,
      borderWidth: 1,
      borderRadius: 4,
    }
  })

  return { labels, datasets }
})

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      position: 'bottom' as const,
      labels: {
        usePointStyle: true,
        pointStyleWidth: 8,
        color: colors.textSecondary,
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
        label: (ctx: any) => ` ${ctx.dataset.label}: ${ctx.raw} min`,
      },
    },
  },
  scales: {
    x: {
      stacked: true,
      grid: { color: colors.gridColor, drawBorder: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
    y: {
      stacked: true,
      title: { display: true, text: 'Minutes', color: colors.textTertiary, font: { size: colors.chartFontSize } },
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
