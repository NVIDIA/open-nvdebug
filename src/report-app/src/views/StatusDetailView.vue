<template>
  <div class="nv-page">
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: pageTitle }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">
      <StatusBadge v-if="statusType !== 'all'" :status="statusType" /> {{ pageTitle }}
    </h2>

    <div class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable
        :columns="columns"
        :data="filteredCollectors"
        :searchable="true"
        @row-click="(row) => router.push(`/dut/${row.dut_id}/${row.group}/${row.id}`)"
      >
        <template #cell-status="{ value }">
          <StatusBadge :status="value" />
        </template>
        <template #cell-execution_time="{ value }">
          {{ typeof value === 'number' ? value.toFixed(1) + 's' : '\u2014' }}
        </template>
        <template #cell-reason="{ value }">
          <ReasonDisplay :text="value" :compact="true" />
        </template>
      </DataTable>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'

const route = useRoute()
const router = useRouter()
const manifestStore = useManifestStore()

const statusType = computed(() => String(route.params.statusType))
const isAll = computed(() => statusType.value === 'all')
const pageTitle = computed(() => isAll.value ? 'All Collectors' : `${statusType.value} Collectors`)

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'dut_id', label: 'DUT' },
  { key: 'group', label: 'Group' },
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  { key: 'execution_time', label: 'Exec Time' },
  { key: 'status', label: 'Status' },
  { key: 'reason', label: 'Reason' },
]

const filteredCollectors = computed(() => {
  const result: any[] = []
  for (const dut of manifestStore.duts) {
    for (const group of dut.collector_groups) {
      for (const c of group.collectors) {
        if (isAll.value || c.status === statusType.value) {
          result.push({
            dut_id: dut.id, group: group.name, id: c.id, name: c.name,
            execution_time: c.execution_time, status: c.status, reason: c.reason || '',
          })
        }
      }
    }
  }
  return result
})
</script>
