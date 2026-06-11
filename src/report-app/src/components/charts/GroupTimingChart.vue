<template>
  <Bar :data="chartData" :options="chartOptions" />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Bar } from 'vue-chartjs'
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from 'chart.js'
import { resolveStatusColor, useThemeColors } from '@/composables/useThemeColors'
import { toHex6 } from '@/utils/color'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend)

const colors = useThemeColors()

const props = defineProps<{
  collectors: Array<{ id: string; name: string; duration: number; status: string }>
}>()

const sorted = computed(() => [...props.collectors].sort((a, b) => b.duration - a.duration))

const chartData = computed(() => ({
  labels: sorted.value.map(c => `${c.id} ${c.name}`),
  datasets: [{
    label: 'Duration (s)',
    data: sorted.value.map(c => +c.duration.toFixed(1)),
    backgroundColor: sorted.value.map(c => toHex6(resolveStatusColor(c.status)) + 'b3'),
    hoverBackgroundColor: sorted.value.map(c => toHex6(resolveStatusColor(c.status))),
    borderColor: sorted.value.map(c => toHex6(resolveStatusColor(c.status))),
    borderWidth: 1,
    borderRadius: 3,
  }],
}))

const chartOptions = computed(() => ({
  indexAxis: 'y' as const,
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { display: false },
    tooltip: {
      backgroundColor: colors.bgElevated || 'rgba(0,0,0,0.85)',
      titleColor: colors.textPrimary,
      bodyColor: colors.textSecondary,
      borderColor: colors.border,
      borderWidth: 1,
      cornerRadius: 8,
      padding: 10,
      callbacks: { label: (ctx: any) => ` ${ctx.raw}s` },
    },
  },
  scales: {
    x: {
      title: { display: true, text: 'Seconds', color: colors.textTertiary, font: { size: colors.chartFontSize } },
      beginAtZero: true,
      grid: { color: colors.border + '30', drawBorder: false },
      ticks: { color: colors.textTertiary, font: { size: colors.chartFontSize } },
    },
    y: {
      grid: { display: false },
      ticks: { color: colors.textSecondary, font: { size: colors.chartFontSizeSm } },
    },
  },
}))
</script>
