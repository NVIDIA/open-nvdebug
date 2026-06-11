<template>
  <div class="chart-container">
    <Doughnut v-if="hasData" :data="chartData" :options="chartOptions" />
    <EmptyState v-else icon="data" title="No data available" />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Doughnut } from 'vue-chartjs'
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js'
import EmptyState from '@/components/common/EmptyState.vue'
import { resolveServiceColor, useThemeColors } from '@/composables/useThemeColors'
import { toHex6 } from '@/utils/color'

ChartJS.register(ArcElement, Tooltip, Legend)

const colors = useThemeColors()

const props = defineProps<{
  services: Array<{ service: string; total_collectors: number }>
}>()

const hasData = computed(() => props.services.some(s => s.total_collectors > 0))
const serviceColors = computed(() => props.services.map(s => toHex6(resolveServiceColor(s.service))))

const chartData = computed(() => ({
  labels: props.services.map(s => s.service),
  datasets: [{
    data: props.services.map(s => s.total_collectors),
    backgroundColor: serviceColors.value.map(color => color + 'b3'),
    hoverBackgroundColor: serviceColors.value,
    borderWidth: 2,
    borderColor: colors.bgPrimary || '#1a1a1a',
    hoverOffset: 6,
  }],
}))

const chartOptions = computed(() => ({
  responsive: true,
  maintainAspectRatio: false,
  cutout: '65%',
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
}))
</script>

<style scoped>
.chart-container {
  height: 260px;
  max-width: 320px;
  margin: 0 auto;
}
</style>
