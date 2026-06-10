<template>
  <div class="nv-page">
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: String(dutId), to: `/dut/${dutId}` }, { label: 'Preflight Checks' }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">Preflight Checks — {{ dutId }}</h2>

    <div v-if="checks.length === 0" class="nv-empty">No preflight data available.</div>

    <div v-else class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable :columns="columns" :data="checks">
        <template #cell-status="{ value }">
          <StatusBadge :status="value" />
        </template>
        <template #cell-details="{ value }">
          <span style="font-size: 0.75rem; color: var(--nv-text-secondary); word-break: break-word; max-width: 400px; display: inline-block;">
            {{ value != null && typeof value === 'object' ? safeStringify(value) : (value || '\u2014') }}
          </span>
        </template>
      </DataTable>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'

function safeStringify(val: unknown): string {
  try { return JSON.stringify(val) } catch { return String(val) }
}

const route = useRoute()
const manifestStore = useManifestStore()

const dutId = computed(() => String(route.params.dutId))

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'name', label: 'Check' },
  { key: 'group', label: 'Group' },
  { key: 'status', label: 'Status' },
  { key: 'details', label: 'Details' },
]

const checks = computed(() => {
  const dutPreflight = manifestStore.preflight?.per_dut.find(p => p.dut_id === dutId.value)
  return dutPreflight?.checks ?? []
})
</script>
