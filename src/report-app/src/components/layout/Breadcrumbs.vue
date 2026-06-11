<template>
  <nav class="nv-breadcrumbs">
    <router-link to="/">Dashboard</router-link>
    <template v-for="(crumb, i) in crumbs" :key="i">
      <span class="nv-breadcrumbs__separator">/</span>
      <router-link
        v-if="crumb.to"
        :to="crumb.to"
      >{{ crumb.label }}</router-link>
      <span v-else class="nv-breadcrumbs__current">{{ crumb.label }}</span>
    </template>
  </nav>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

interface Crumb {
  label: string
  to?: string
}

const route = useRoute()

const crumbs = computed<Crumb[]>(() => {
  const result: Crumb[] = []
  const params = route.params

  if (params.dutId) {
    result.push({ label: String(params.dutId), to: `/dut/${params.dutId}` })
  }
  if (params.group) {
    result.push({ label: String(params.group), to: `/dut/${params.dutId}/${params.group}` })
  }
  if (params.collectorId) {
    result.push({ label: String(params.collectorId) })
  }
  if (params.statusType) {
    result.push({ label: `Status: ${params.statusType}` })
  }
  if (params.encodedPath) {
    const path = String(params.encodedPath)
    const fileName = path.split('/').pop() || path
    result.push({ label: fileName })
  }

  // Named routes without params
  const namedCrumbs: Record<string, string> = {
    'file-map': 'File Map',
    'timing': 'Timing Analysis',
    'gantt': 'Gantt Timeline',
    'errors': 'Errors',
    'diff': 'Diff',
    'dependencies': 'Dependencies',
    'heatmap': 'Health Heatmap',
    'compare': 'DUT Comparison',
    'correlate': 'Log Correlation',
    'compare-runs': 'Run Comparison',
  }

  const routeName = String(route.name || '')
  if (namedCrumbs[routeName] && result.length === 0) {
    result.push({ label: namedCrumbs[routeName] })
  }

  return result
})
</script>
