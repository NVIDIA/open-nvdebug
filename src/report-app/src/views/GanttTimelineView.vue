<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Execution Timeline' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 20px;">Execution Timeline</h2>

    <VerticalExecutionTimeline
      v-if="timing && timing.per_dut.length > 0"
      :per-dut="timing.per_dut"
      :total-duration="timing.total_duration"
      max-height="calc(100vh - 230px)"
    />
    <EmptyState
      v-else
      icon="data"
      title="No timing data available"
      description="Timing data is recorded during collection. Run a collection to see the execution timeline."
    />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import VerticalExecutionTimeline from '@/components/charts/VerticalExecutionTimeline.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import EmptyState from '@/components/common/EmptyState.vue'

const manifestStore = useManifestStore()
const timing = computed(() => manifestStore.timing)
</script>
