<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'DUT Comparison' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 20px;">DUT Comparison</h2>

    <!-- DUT Selector (pills) -->
    <div class="nv-glass--subtle nv-filter-bar" style="margin-bottom: 16px; padding: 10px 16px;">
      <span style="font-size: 0.8125rem; color: var(--nv-text-secondary); margin-right: 4px;">Select DUTs to compare:</span>
      <DutPillSelector
        v-model="selectedDuts"
        :options="dutOptions"
        :multiple="true"
        :max="4"
      />
    </div>

    <div v-if="selectedDuts.length < 2" class="nv-glass" style="padding: 40px; text-align: center; color: var(--nv-text-secondary); border-radius: 12px;">
      Select at least 2 DUTs to compare.
    </div>

    <template v-else>
      <!-- System Info Comparison -->
      <div class="nv-card" style="margin-bottom: 16px;">
        <h3 class="nv-section-subtitle">System Info</h3>
        <div class="nv-table-viewport">
          <table class="nv-table">
            <thead>
              <tr>
                <th>Field</th>
                <th v-for="dutId in selectedDuts" :key="dutId">{{ dutId }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="field in systemFields" :key="field.key">
                <td>{{ field.label }}</td>
                <td v-for="dutId in selectedDuts" :key="dutId" :style="{ background: isDifferent(field.key, dutId) ? 'var(--nv-warning-muted)' : 'transparent' }">
                  {{ getSystemField(dutId, field.key) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Status Comparison (DataTable) -->
      <div class="nv-card" style="margin-bottom: 16px;">
        <h3 class="nv-section-subtitle">Collector Status Comparison</h3>
        <DataTable :columns="statusColumns" :data="statusTableData" :searchable="true">
          <template v-for="dutId in selectedDuts" :key="dutId" v-slot:[cellSlot(dutId)]="{ value }">
            <StatusBadge v-if="value" :status="value" />
            <span v-else style="color: var(--nv-text-secondary);">&mdash;</span>
          </template>
        </DataTable>
      </div>

      <!-- Timing Comparison -->
      <div class="nv-card">
        <h3 class="nv-section-subtitle">Timing Comparison</h3>
        <div class="nv-table-viewport">
          <table class="nv-table">
            <thead>
              <tr>
                <th>Metric</th>
                <th v-for="dutId in selectedDuts" :key="dutId">{{ dutId }}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Total Execution Time</td>
                <td v-for="dutId in selectedDuts" :key="dutId">{{ getDut(dutId)?.execution_time.toFixed(1) }}s</td>
              </tr>
              <tr>
                <td>Log Size</td>
                <td v-for="dutId in selectedDuts" :key="dutId">{{ formatBytes(getDut(dutId)?.log_size ?? 0) }}</td>
              </tr>
              <tr>
                <td>Success Count</td>
                <td v-for="dutId in selectedDuts" :key="dutId">{{ getDut(dutId)?.status_summary.success ?? 0 }}</td>
              </tr>
              <tr>
                <td>Error Count</td>
                <td v-for="dutId in selectedDuts" :key="dutId">{{ getDut(dutId)?.status_summary.error ?? 0 }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import StatusBadge from '@/components/common/StatusBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import DataTable from '@/components/common/DataTable.vue'
import type { Column } from '@/components/common/DataTable.vue'
import DutPillSelector from '@/components/common/DutPillSelector.vue'
import type { PillOption } from '@/components/common/DutPillSelector.vue'
import { naturalCompare } from '@/utils/naturalSort'

const manifestStore = useManifestStore()
const selectedDuts = ref<string[]>([])

const dutOptions = computed<PillOption[]>(() =>
  manifestStore.duts.map(d => ({ id: d.id, label: d.id, status: d.overall_status }))
)

const systemFields = [
  { key: 'model', label: 'Model' },
  { key: 'part_number', label: 'Part Number' },
  { key: 'serial_number', label: 'Serial Number' },
  { key: 'baseboard', label: 'Baseboard' },
]

function getDut(id: string) { return manifestStore.dutById(id) }

function getSystemField(dutId: string, field: string): string {
  const dut = getDut(dutId)
  if (!dut) return '\u2014'
  if (field === 'baseboard') return dut.baseboard
  return (dut.system_info as any)?.[field] ?? '\u2014'
}

function isDifferent(field: string, dutId: string): boolean {
  const values = selectedDuts.value.map(id => getSystemField(id, field))
  const val = getSystemField(dutId, field)
  return values.some(v => v !== val && v !== '\u2014' && val !== '\u2014')
}

const allCollectorIds = computed(() => {
  const ids = new Set<string>()
  for (const dutId of selectedDuts.value) {
    const dut = getDut(dutId)
    if (dut) {
      for (const g of dut.collector_groups) {
        for (const c of g.collectors) ids.add(c.id)
      }
    }
  }
  return [...ids].sort(naturalCompare)
})

function getCollectorStatus(dutId: string, collectorId: string): string | null {
  const dut = getDut(dutId)
  if (!dut) return null
  for (const g of dut.collector_groups) {
    const c = g.collectors.find(c => c.id === collectorId)
    if (c) return c.status
  }
  return null
}

const statusColumns = computed<Column[]>(() => [
  { key: 'collector', label: 'Collector' },
  ...selectedDuts.value.map(dutId => ({ key: `dut_${dutId}`, label: dutId })),
])

const statusTableData = computed(() =>
  allCollectorIds.value.map(cid => {
    const row: Record<string, any> = { collector: cid }
    for (const dutId of selectedDuts.value) {
      row[`dut_${dutId}`] = getCollectorStatus(dutId, cid)
    }
    return row
  })
)

function cellSlot(dutId: string): string {
  return `cell-dut_${dutId}`
}

function formatBytes(b: number): string {
  if (b < 1024 * 1024) return (b / 1024).toFixed(0) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}
</script>
