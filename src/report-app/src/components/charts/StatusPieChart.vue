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

ChartJS.register(ArcElement, Tooltip, Legend)

const props = defineProps<{
  counts: Record<string, number>
}>()

const router = useRouter()
const chartRef = ref()
const colors = useThemeColors()

const statusOrder = ['success', 'error', 'partial', 'skipped', 'not_ran']

const hasData = computed(() => Object.values(props.counts).some(v => v > 0))

const chartData = computed(() => {
  const labels = statusOrder.filter(s => (props.counts[s] ?? 0) > 0)
  return {
    labels: labels.map(s => s.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())),
    datasets: [{
      data: labels.map(s => props.counts[s] ?? 0),
      backgroundColor: labels.map(s => resolveStatusColor(s) + 'b3'),
      hoverBackgroundColor: labels.map(s => resolveStatusColor(s)),
      borderWidth: 2,
      borderColor: colors.bgPrimary || '#1a1a1a',
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
        color: colors.textSecondary,
        font: { size: colors.chartFontSize },
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
    const labels = statusOrder.filter(s => (props.counts[s] ?? 0) > 0)
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
