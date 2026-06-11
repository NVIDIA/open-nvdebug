<template>
  <div class="nv-page">
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: String(dutId), to: `/dut/${dutId}` }, { label: 'Firmware' }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">Firmware — {{ dutId }}</h2>

    <div v-if="firmware.length === 0" class="nv-empty">No firmware data available.</div>

    <div v-else class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable :columns="columns" :data="firmware" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'

const route = useRoute()
const manifestStore = useManifestStore()

const dutId = computed(() => String(route.params.dutId))

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  { key: 'version', label: 'Version' },
]

const firmware = computed(() => {
  const dut = manifestStore.dutById(dutId.value)
  return (dut?.system_info?.firmware ?? []).map(f => ({
    id: f.id || f.component || '\u2014',
    name: f.name || f.id || f.component || '\u2014',
    version: f.version || '\u2014',
  }))
})
</script>
