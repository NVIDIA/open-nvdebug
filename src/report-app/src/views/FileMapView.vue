<template>
  <div class="nv-page">
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: 'File Map' }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">File Map</h2>

    <!-- Stats -->
    <div class="stats-row">
      <div class="nv-glass nv-glass--accent stat-card">
        <div class="stat-value">{{ fileIndex.length }}</div>
        <div class="stat-label">Total Files</div>
      </div>
      <div class="nv-glass nv-glass--accent stat-card">
        <div class="stat-value">{{ dutCount }}</div>
        <div class="stat-label">DUTs</div>
      </div>
      <div class="nv-glass nv-glass--accent stat-card">
        <div class="stat-value">{{ groupCount }}</div>
        <div class="stat-label">Collector Groups</div>
      </div>
    </div>

    <!-- View toggle + Filters -->
    <div class="nv-filter-bar">
      <div class="nv-toggle-group">
        <button
          @click="viewMode = 'table'"
          :class="['nv-toggle-group__btn', { 'nv-toggle-group__btn--active': viewMode === 'table' }]"
        >Table</button>
        <button
          @click="viewMode = 'tree'"
          :class="['nv-toggle-group__btn', { 'nv-toggle-group__btn--active': viewMode === 'tree' }]"
        >Tree</button>
      </div>

      <!-- DUT filter -->
      <select v-model="dutFilter" class="nv-select">
        <option value="">All DUTs</option>
        <option v-for="dut in dutNames" :key="dut" :value="dut">{{ dut }}</option>
      </select>

      <!-- Group filter -->
      <select v-model="groupFilter" class="nv-select">
        <option value="">All Groups</option>
        <option v-for="g in groupNames" :key="g" :value="g">{{ g }}</option>
      </select>

      <span style="flex: 1;"></span>

      <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="exportCSV" title="Export filtered file list as CSV">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style="margin-right: 4px;"><path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/></svg>
        Export CSV
      </button>
      <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="copyShareUrl" title="Copy shareable URL with current filters">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" style="margin-right: 4px;"><path d="M4.715 6.542 3.343 7.914a3 3 0 1 0 4.243 4.243l1.828-1.829A3 3 0 0 0 8.586 5.5L8 6.086a1.002 1.002 0 0 0-.154.199 2 2 0 0 1 .861 3.337L6.88 11.45a2 2 0 1 1-2.83-2.83l.793-.792a4.018 4.018 0 0 1-.128-1.287z"/><path d="M6.586 4.672A3 3 0 0 0 7.414 9.5l.775-.776a2 2 0 0 1-.896-3.346L9.12 3.55a2 2 0 1 1 2.83 2.83l-.793.792c.112.42.155.855.128 1.287l1.372-1.372a3 3 0 1 0-4.243-4.243L6.586 4.672z"/></svg>
        Share
      </button>
    </div>

    <!-- Table View -->
    <div v-if="viewMode === 'table'" class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable
        :columns="tableColumns"
        :data="filteredTableData"
        :searchable="true"
        @row-click="openFile"
      >
        <template #cell-type="{ value }">
          <span style="font-size: 0.75rem; color: var(--nv-text-secondary);">{{ value }}</span>
        </template>
        <template #cell-size="{ value }">
          {{ formatBytes(value) }}
        </template>
      </DataTable>
    </div>

    <!-- Tree View -->
    <div v-else class="nv-glass" style="padding: 8px; max-height: 600px; overflow: auto;">
      <FileTree :files="filteredFiles" @file-click="openFile" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { useFilterStore } from '@/stores/filters'
import DataTable from '@/components/common/DataTable.vue'
import FileTree from '@/components/common/FileTree.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import { showToast } from '@/composables/useToast'
import { copyToClipboard } from '@/utils/clipboard'

interface Column {
  key: string
  label: string
  sortable?: boolean
}

const manifestStore = useManifestStore()
const filterStore = useFilterStore()
const router = useRouter()
const route = useRoute()

const saved = filterStore.loadFilters('file-map')
const viewMode = ref<'table' | 'tree'>((saved.viewMode as string) === 'tree' ? 'tree' : 'table')
const dutFilter = ref((saved.dutFilter as string) || '')
const groupFilter = ref((saved.groupFilter as string) || '')

const fileIndex = computed(() => manifestStore.fileIndex)

const dutNames = computed(() => [...new Set(fileIndex.value.map(f => f.dut_id))].sort())
const groupNames = computed(() => [...new Set(fileIndex.value.map(f => f.collector_group).filter(Boolean))].sort())
const dutCount = computed(() => dutNames.value.length)
const groupCount = computed(() => groupNames.value.length)

const filteredFiles = computed(() => {
  let files = fileIndex.value
  if (dutFilter.value) files = files.filter(f => f.dut_id === dutFilter.value)
  if (groupFilter.value) files = files.filter(f => f.collector_group === groupFilter.value)
  return files
})

const filteredTableData = computed(() =>
  filteredFiles.value.map(f => ({
    dut_id: f.dut_id,
    collector_group: f.collector_group,
    collector: f.collector_id ? `${f.collector_id} ${f.collector_name}` : f.collector_name,
    path: f.path,
    type: f.type,
    size: f.size,
  }))
)

const tableColumns: Column[] = [
  { key: 'dut_id', label: 'DUT' },
  { key: 'collector_group', label: 'Group' },
  { key: 'collector', label: 'Collector' },
  { key: 'path', label: 'File Path' },
  { key: 'type', label: 'Type' },
  { key: 'size', label: 'Size' },
]

function openFile(row: any) {
  const path = typeof row === 'string' ? row : row.path
  router.push(`/file/${encodeURIComponent(path)}`)
}

// Sync filter state to URL query params
onMounted(() => {
  const q = route.query
  if (q.dut) dutFilter.value = String(q.dut)
  if (q.group) groupFilter.value = String(q.group)
  if (q.view === 'tree') viewMode.value = 'tree'
})

watch([dutFilter, groupFilter, viewMode], () => {
  const query: Record<string, string> = {}
  if (dutFilter.value) query.dut = dutFilter.value
  if (groupFilter.value) query.group = groupFilter.value
  if (viewMode.value !== 'table') query.view = viewMode.value
  router.replace({ query })
  filterStore.saveFilters('file-map', {
    dutFilter: dutFilter.value,
    groupFilter: groupFilter.value,
    viewMode: viewMode.value,
  })
})

function exportCSV() {
  const headers = ['DUT', 'Group', 'Collector', 'Path', 'Type', 'Size']
  const rows = filteredTableData.value.map(r =>
    [r.dut_id, r.collector_group, r.collector, r.path, r.type, r.size].map(v => `"${String(v).replace(/"/g, '""')}"`)
  )
  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `nvdebug-files-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

async function copyShareUrl() {
  try {
    await copyToClipboard(window.location.href)
    showToast('URL copied to clipboard', 'success')
  } catch {
    showToast('Copy failed', 'error')
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i]
}
</script>

<style scoped>
.stats-row {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
}

.stat-card {
  text-align: center;
  min-width: 120px;
  padding: 16px 24px;
}

.stat-value {
  font-size: 1.375rem;
  font-weight: 700;
  color: var(--nv-text-primary);
}

.stat-label {
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  margin-top: 2px;
}
</style>
