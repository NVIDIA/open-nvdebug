<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Health Heatmap' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 20px;">Health Heatmap</h2>

    <!-- Filters -->
    <div class="nv-glass--subtle nv-filter-bar" style="margin-bottom: 16px;">
      <select v-model="serviceFilter" class="nv-select">
        <option value="">All Services</option>
        <option v-for="s in allServices" :key="s" :value="s">{{ s }}</option>
      </select>
      <button
        v-for="status in visibleStatusOptions"
        :key="status"
        :class="['hm-pill', { 'hm-pill--active': visibleStatuses.has(status) }]"
        :style="{ '--pill-color': STATUS_COLORS[status] ?? 'var(--nv-bg-tertiary)' }"
        @click="toggleStatus(status)"
      >
        <span class="hm-pill__dot" :style="{ background: visibleStatuses.has(status) ? (STATUS_COLORS[status] ?? 'var(--nv-bg-tertiary)') : 'var(--nv-text-tertiary)' }"></span>
        {{ status }}
        <span class="hm-pill__count">{{ statusCounts[status] ?? 0 }}</span>
      </button>
      <span style="flex: 1;" />
      <button
        :class="['hm-pill', { 'hm-pill--active': !hideNotRan }]"
        style="--pill-color: var(--nv-text-tertiary);"
        @click="hideNotRan = !hideNotRan"
      >
        {{ hideNotRan ? 'Show not_ran' : 'Hide not_ran' }}
      </button>
    </div>

    <!-- Grid -->
    <div class="nv-card" style="overflow: hidden;">
      <div class="hm-viewport">
        <table class="hm-table">
          <thead>
            <tr>
              <th class="hm-table__corner">DUT</th>
              <template v-for="(group, gi) in groupedColumns" :key="gi">
                <th
                  :colspan="group.cols.length"
                  class="hm-table__group-header"
                  :style="{ color: SERVICE_COLORS[group.service] ?? 'var(--nv-text-secondary)' }"
                >
                  {{ group.service }}
                </th>
              </template>
              <th class="hm-table__corner hm-table__summary-header">Pass %</th>
            </tr>
            <tr>
              <th class="hm-table__corner hm-table__corner--sub"></th>
              <template v-for="(group, gi) in groupedColumns" :key="'h' + gi">
                <th
                  v-for="col in group.cols"
                  :key="col.id"
                  class="hm-table__col-header"
                >
                  <span
                    class="hm-table__col-text"
                    :title="`${col.id} — ${col.name}`"
                    :style="{ color: SERVICE_COLORS[col.group] ?? 'var(--nv-text-secondary)' }"
                  >{{ col.id }}</span>
                </th>
              </template>
              <th class="hm-table__corner hm-table__corner--sub"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="dut in manifestStore.duts" :key="dut.id">
              <td class="hm-table__dut-cell">
                <router-link :to="`/dut/${dut.id}`" style="color: var(--nv-accent); text-decoration: none;">{{ dut.id }}</router-link>
              </td>
              <template v-for="(group, gi) in groupedColumns" :key="'b' + gi">
                <td
                  v-for="col in group.cols"
                  :key="col.id"
                  class="hm-table__cell"
                  :style="{ background: getCellColor(dut.id, col.id) }"
                  :title="getCellTooltip(dut.id, col.id)"
                  @click="navigateToCollector(dut.id, col.group, col.id)"
                >
                  <span v-if="getCellStatus(dut.id, col.id) === 'error'" class="hm-table__error-icon">!</span>
                </td>
              </template>
              <td class="hm-table__summary-cell" :style="{ color: passRateColor(dutPassRate(dut.id)) }">
                {{ dutPassRate(dut.id) }}%
              </td>
            </tr>

            <!-- Summary row -->
            <tr class="hm-table__summary-row">
              <td class="hm-table__dut-cell hm-table__dut-cell--summary">Pass %</td>
              <template v-for="(group, gi) in groupedColumns" :key="'s' + gi">
                <td
                  v-for="col in group.cols"
                  :key="col.id"
                  class="hm-table__cell hm-table__cell--summary"
                  :title="`${col.id}: ${colPassRate(col.id)}% pass rate across DUTs`"
                >
                  <span :style="{ color: passRateColor(colPassRate(col.id)), fontWeight: 600, fontSize: '0.625rem' }">
                    {{ colPassRate(col.id) }}%
                  </span>
                </td>
              </template>
              <td class="hm-table__summary-cell hm-table__summary-cell--grand" :style="{ color: passRateColor(grandPassRate) }">
                {{ grandPassRate }}%
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Legend -->
    <div class="nv-glass--subtle hm-legend">
      <span v-for="(color, status) in STATUS_COLORS" :key="status" class="hm-legend__item">
        <span class="hm-legend__swatch" :style="{ background: color }"></span>
        {{ status }}
      </span>
      <span class="hm-legend__item">
        <span class="hm-legend__swatch" style="background: var(--nv-bg-tertiary);"></span>
        N/A
      </span>
    </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { STATUS_COLORS, SERVICE_COLORS } from '@/types/colors'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const manifestStore = useManifestStore()
const router = useRouter()

const serviceFilter = ref('')
const hideNotRan = ref(true)
const statusOptions = ['success', 'error', 'partial', 'skipped', 'not_ran']
const visibleStatuses = reactive(new Set(statusOptions))

const visibleStatusOptions = computed(() =>
  hideNotRan.value ? statusOptions.filter(s => s !== 'not_ran') : statusOptions
)

function toggleStatus(status: string) {
  if (visibleStatuses.has(status)) visibleStatuses.delete(status)
  else visibleStatuses.add(status)
}

const statusCounts = computed(() => {
  const counts: Record<string, number> = {}
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        counts[c.status] = (counts[c.status] ?? 0) + 1
      }
    }
  }
  return counts
})

const allServices = computed(() => {
  const services = new Set<string>()
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) services.add(g.name)
  }
  return [...services].sort()
})

interface ColDef { id: string; name: string; group: string }

const columns = computed<ColDef[]>(() => {
  const seen = new Map<string, ColDef>()
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) {
      if (serviceFilter.value && g.name !== serviceFilter.value) continue
      for (const c of g.collectors) {
        if (hideNotRan.value && isGlobalNotRan(c.id)) continue
        if (!seen.has(c.id)) seen.set(c.id, { id: c.id, name: c.name, group: g.name })
      }
    }
  }
  return [...seen.values()].sort((a, b) => {
    const gCmp = a.group.localeCompare(b.group)
    return gCmp !== 0 ? gCmp : a.id.localeCompare(b.id)
  })
})

function isGlobalNotRan(collectorId: string): boolean {
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.id === collectorId && String(c.status) !== 'not_ran') return false
      }
    }
  }
  return true
}

interface GroupedCols { service: string; cols: ColDef[] }

const groupedColumns = computed<GroupedCols[]>(() => {
  const groups: GroupedCols[] = []
  let current: GroupedCols | null = null
  for (const col of columns.value) {
    if (!current || current.service !== col.group) {
      current = { service: col.group, cols: [] }
      groups.push(current)
    }
    current.cols.push(col)
  }
  return groups
})

const statusMap = computed(() => {
  const map = new Map<string, Map<string, { status: string; name: string; duration: number }>>()
  for (const dut of manifestStore.duts) {
    const dutMap = new Map<string, { status: string; name: string; duration: number }>()
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        dutMap.set(c.id, { status: c.status, name: c.name, duration: c.execution_time })
      }
    }
    map.set(dut.id, dutMap)
  }
  return map
})

function getCellStatus(dutId: string, collectorId: string): string | null {
  return statusMap.value.get(dutId)?.get(collectorId)?.status ?? null
}

function getCellColor(dutId: string, collectorId: string): string {
  const status = getCellStatus(dutId, collectorId)
  if (!status) return 'var(--nv-bg-tertiary)'
  if (!visibleStatuses.has(status)) return 'var(--nv-bg-tertiary)'
  return STATUS_COLORS[status] ?? 'var(--nv-bg-tertiary)'
}

function getCellTooltip(dutId: string, collectorId: string): string {
  const info = statusMap.value.get(dutId)?.get(collectorId)
  if (!info) return `${collectorId}: Not applicable`
  return `${collectorId} — ${info.name}\nStatus: ${info.status}\nDuration: ${info.duration.toFixed(1)}s`
}

function navigateToCollector(dutId: string, group: string, collectorId: string) {
  router.push(`/dut/${dutId}/${group}/${collectorId}`)
}

const flatColumns = computed(() => groupedColumns.value.flatMap(g => g.cols))

function dutPassRate(dutId: string): number {
  const dutMap = statusMap.value.get(dutId)
  if (!dutMap) return 0
  let pass = 0, total = 0
  for (const col of flatColumns.value) {
    const info = dutMap.get(col.id)
    if (!info || String(info.status) === 'not_ran') continue
    total++
    if (info.status === 'success') pass++
  }
  return total === 0 ? 0 : Math.round((pass / total) * 100)
}

function colPassRate(collectorId: string): number {
  let pass = 0, total = 0
  for (const dut of manifestStore.duts) {
    const info = statusMap.value.get(dut.id)?.get(collectorId)
    if (!info || String(info.status) === 'not_ran') continue
    total++
    if (info.status === 'success') pass++
  }
  return total === 0 ? 0 : Math.round((pass / total) * 100)
}

const grandPassRate = computed(() => {
  let pass = 0, total = 0
  for (const dut of manifestStore.duts) {
    for (const col of flatColumns.value) {
      const info = statusMap.value.get(dut.id)?.get(col.id)
      if (!info || String(info.status) === 'not_ran') continue
      total++
      if (info.status === 'success') pass++
    }
  }
  return total === 0 ? 0 : Math.round((pass / total) * 100)
})

function passRateColor(pct: number): string {
  if (pct >= 90) return 'var(--nv-success)'
  if (pct >= 70) return 'var(--nv-warning)'
  return 'var(--nv-error)'
}
</script>

<style scoped>
.hm-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: 14px;
  font-size: 0.6875rem;
  border: 1px solid var(--nv-glass-border);
  background: transparent;
  color: var(--nv-text-tertiary);
  cursor: pointer;
  transition: all 0.15s ease;
  opacity: 0.5;
}
.hm-pill:hover { opacity: 0.8; }
.hm-pill--active {
  border-color: var(--pill-color);
  background: color-mix(in srgb, var(--pill-color) 15%, transparent);
  color: var(--pill-color);
  opacity: 1;
  font-weight: 600;
}
.hm-pill__dot {
  width: 8px;
  height: 8px;
  border-radius: 2px;
  flex-shrink: 0;
}
.hm-pill__count {
  font-family: var(--nv-font-mono);
  font-size: 0.5625rem;
  opacity: 0.7;
}

.hm-viewport {
  max-height: calc(100vh - 300px);
  overflow: auto;
}

.hm-table {
  font-size: 0.6875rem;
  border-collapse: separate;
  border-spacing: 0;
  width: max-content;
  min-width: 100%;
}
.hm-table th,
.hm-table td {
  border: 1px solid var(--nv-glass-border);
  padding: 0;
}

.hm-table__group-header {
  text-align: center;
  padding: 4px 6px;
  font-size: 0.625rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  position: sticky;
  top: 0;
  z-index: 2;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(8px);
  border-bottom: 2px solid currentColor;
}

.hm-table__corner {
  position: sticky;
  left: 0;
  top: 0;
  z-index: 3;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(8px);
  padding: 6px 10px;
  font-weight: 600;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.hm-table__corner--sub {
  top: auto;
}
.hm-table__summary-header {
  left: auto;
  position: sticky;
  top: 0;
  right: 0;
  z-index: 2;
  text-align: center;
  min-width: 50px;
}

.hm-table__col-header {
  position: sticky;
  top: 26px;
  z-index: 2;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(8px);
  min-width: 28px;
  height: 90px;
  padding: 2px;
  vertical-align: bottom;
}
.hm-table__col-text {
  display: block;
  writing-mode: vertical-rl;
  transform: rotate(180deg);
  font-weight: 600;
  font-size: 0.625rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-height: 80px;
}

.hm-table__dut-cell {
  font-weight: 600;
  white-space: nowrap;
  position: sticky;
  left: 0;
  z-index: 1;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(8px);
  padding: 4px 10px;
}
.hm-table__dut-cell--summary {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--nv-text-tertiary);
}

.hm-table__cell {
  cursor: pointer;
  min-width: 28px;
  min-height: 28px;
  width: 28px;
  height: 28px;
  text-align: center;
  vertical-align: middle;
  transition: opacity 0.15s ease, box-shadow 0.15s ease;
}
.hm-table__cell:hover {
  opacity: 0.8;
  box-shadow: inset 0 0 0 2px var(--nv-accent);
}
.hm-table__cell--summary {
  background: var(--nv-glass-bg-light) !important;
  cursor: default;
  text-align: center;
  vertical-align: middle;
}
.hm-table__error-icon {
  color: #fff;
  font-weight: 700;
  font-size: 0.6875rem;
  text-shadow: 0 0 2px rgba(0,0,0,0.3);
}

.hm-table__summary-cell {
  text-align: center;
  font-weight: 700;
  font-size: 0.6875rem;
  font-family: var(--nv-font-mono);
  min-width: 50px;
  padding: 2px 6px;
}
.hm-table__summary-cell--grand {
  background: var(--nv-glass-bg-light);
  font-size: 0.75rem;
}

.hm-table__summary-row td {
  border-top: 2px solid var(--nv-glass-border);
}

.hm-legend {
  display: flex;
  gap: 16px;
  margin-top: 12px;
  padding: 10px 16px;
  border-radius: 8px;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  flex-wrap: wrap;
}
.hm-legend__item {
  display: flex;
  align-items: center;
  gap: 4px;
}
.hm-legend__swatch {
  width: 12px;
  height: 12px;
  border-radius: 2px;
  display: inline-block;
  flex-shrink: 0;
}
</style>
