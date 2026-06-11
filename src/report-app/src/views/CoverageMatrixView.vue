<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 6px 12px; margin: 0; font-size: 0.5625rem;">DUTs</h4>
      <div style="padding: 4px 0; max-height: 240px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': selectedDuts.length === 0 }"
          style="font-size: 0.6875rem; cursor: pointer;"
          @click="selectedDuts = []"
        >All DUTs ({{ manifestStore.duts.length }})</a>
        <a
          v-for="d in manifestStore.duts"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': selectedDuts.includes(d.id) }"
          style="font-size: 0.6875rem; cursor: pointer;"
          @click="toggleDut(d.id)"
        >{{ d.id }}</a>
      </div>
    </div>
    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Building coverage matrix..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Coverage Matrix' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 8px;">Collector Coverage Matrix</h2>
        <p style="font-size: 0.75rem; color: var(--nv-text-tertiary); margin: 0 0 16px;">
          Showing {{ duts.length }} of {{ manifestStore.duts.length }} DUTs &times; {{ filteredCollectorIds.length }} of {{ collectorIds.length }} collectors &middot; Hover cells for details &middot; Click to navigate
        </p>

        <!-- Filters -->
        <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; align-items: center;">
          <select v-model="serviceFilter" class="nv-input nv-input--sm" style="font-size: 0.75rem; max-width: 180px;">
            <option value="">All Services</option>
            <option v-for="s in serviceTypes" :key="s" :value="s">{{ s }}</option>
          </select>
          <select v-model="statusFilter" class="nv-input nv-input--sm" style="font-size: 0.75rem; max-width: 140px;">
            <option value="">All Statuses</option>
            <option value="success">Success</option>
            <option value="error">Error</option>
            <option value="partial">Partial</option>
            <option value="skipped">Skipped</option>
            <option value="not_ran">Not Ran</option>
          </select>
          <label style="font-size: 0.6875rem; color: var(--nv-text-secondary); display: flex; align-items: center; gap: 4px;">
            <input type="checkbox" v-model="hideNotRan" /> Hide not-ran
          </label>
        </div>

        <!-- Matrix -->
        <div class="cm-wrapper" ref="matrixRef">
          <table class="cm-table">
            <thead>
              <tr>
                <th class="cm-th cm-th--corner">DUT</th>
                <th v-for="cid in filteredCollectorIds" :key="cid" class="cm-th cm-th--col" :title="cid">
                  <span class="cm-th__text">{{ cid }}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="dut in duts" :key="dut.id">
                <td class="cm-td cm-td--row" @click="router.push(`/dut/${encodeURIComponent(dut.id)}`)">{{ dut.id }}</td>
                <td
                  v-for="cid in filteredCollectorIds"
                  :key="cid"
                  :class="['cm-cell', `cm-cell--${cellStatus(dut.id, cid)}`]"
                  :title="cellTooltip(dut.id, cid)"
                  @click="navigateToCollector(dut.id, cid)"
                ></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Legend -->
        <div style="display: flex; gap: 12px; margin-top: 12px; font-size: 0.6875rem; color: var(--nv-text-secondary); flex-wrap: wrap;">
          <span style="display: flex; align-items: center; gap: 4px;"><span class="cm-legend cm-legend--success"></span> Success</span>
          <span style="display: flex; align-items: center; gap: 4px;"><span class="cm-legend cm-legend--error"></span> Error</span>
          <span style="display: flex; align-items: center; gap: 4px;"><span class="cm-legend cm-legend--partial"></span> Partial</span>
          <span style="display: flex; align-items: center; gap: 4px;"><span class="cm-legend cm-legend--skipped"></span> Skipped</span>
          <span style="display: flex; align-items: center; gap: 4px;"><span class="cm-legend cm-legend--not_ran"></span> Not Ran</span>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { naturalCompare } from '@/utils/naturalSort'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const router = useRouter()
const manifestStore = useManifestStore()
const matrixRef = ref<HTMLElement>()
const serviceFilter = ref('')
const statusFilter = ref('')
const hideNotRan = ref(false)
const selectedDuts = ref<string[]>([])

function toggleDut(id: string) {
  const idx = selectedDuts.value.indexOf(id)
  if (idx >= 0) selectedDuts.value.splice(idx, 1)
  else selectedDuts.value.push(id)
}

const duts = computed(() =>
  selectedDuts.value.length === 0
    ? manifestStore.duts
    : manifestStore.duts.filter(d => selectedDuts.value.includes(d.id))
)

interface CellInfo {
  status: string
  time: number
  reason: string
  group: string
  serviceType: string
}

const matrixMap = computed(() => {
  const map = new Map<string, CellInfo>()
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        map.set(`${dut.id}::${c.id}`, {
          status: c.status,
          time: c.execution_time,
          reason: c.reason,
          group: g.name,
          serviceType: g.service_type || g.name,
        })
      }
    }
  }
  return map
})

const serviceTypes = computed(() => {
  const set = new Set<string>()
  for (const info of matrixMap.value.values()) set.add(info.serviceType)
  return [...set].sort()
})

const collectorIds = computed(() => {
  const ids = new Set<string>()
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) ids.add(c.id)
    }
  }
  return [...ids].sort(naturalCompare)
})

const filteredCollectorIds = computed(() => {
  let ids = collectorIds.value
  if (serviceFilter.value) {
    ids = ids.filter(cid => {
      for (const dut of manifestStore.duts) {
        const info = matrixMap.value.get(`${dut.id}::${cid}`)
        if (info && info.serviceType === serviceFilter.value) return true
      }
      return false
    })
  }
  if (statusFilter.value) {
    ids = ids.filter(cid => {
      for (const dut of manifestStore.duts) {
        const info = matrixMap.value.get(`${dut.id}::${cid}`)
        if (info && info.status === statusFilter.value) return true
      }
      return false
    })
  }
  if (hideNotRan.value) {
    ids = ids.filter(cid => {
      for (const dut of manifestStore.duts) {
        const info = matrixMap.value.get(`${dut.id}::${cid}`)
        if (info && info.status !== 'not_ran') return true
      }
      return false
    })
  }
  return ids
})

function cellStatus(dutId: string, cid: string): string {
  return matrixMap.value.get(`${dutId}::${cid}`)?.status ?? 'empty'
}

function cellTooltip(dutId: string, cid: string): string {
  const info = matrixMap.value.get(`${dutId}::${cid}`)
  if (!info) return `${cid} — not present`
  let tip = `${cid} on ${dutId}: ${info.status}`
  if (info.time > 0) tip += ` (${info.time.toFixed(1)}s)`
  if (info.reason) tip += `\n${info.reason}`
  return tip
}

function navigateToCollector(dutId: string, cid: string) {
  const info = matrixMap.value.get(`${dutId}::${cid}`)
  if (info) {
    router.push(`/dut/${encodeURIComponent(dutId)}/${encodeURIComponent(info.group)}/${encodeURIComponent(cid)}`)
  }
}
</script>

<style scoped>
.cm-wrapper {
  overflow: auto;
  max-height: calc(100vh - 260px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
}
.cm-table {
  border-collapse: collapse;
  font-size: 0.6875rem;
}
.cm-th {
  position: sticky;
  top: 0;
  background: var(--nv-surface-primary);
  z-index: 2;
  padding: 4px;
  border-bottom: 1px solid var(--nv-glass-border);
  font-weight: 600;
  color: var(--nv-text-secondary);
}
.cm-th--corner {
  position: sticky;
  left: 0;
  z-index: 3;
  min-width: 80px;
  text-align: left;
  padding-left: 8px;
}
.cm-th--col {
  writing-mode: vertical-lr;
  text-orientation: mixed;
  max-width: 18px;
  min-width: 18px;
  height: 80px;
  white-space: nowrap;
  overflow: hidden;
}
.cm-th__text {
  display: inline-block;
  transform: rotate(180deg);
}
.cm-td--row {
  position: sticky;
  left: 0;
  background: var(--nv-surface-primary);
  z-index: 1;
  padding: 2px 8px;
  font-weight: 600;
  color: var(--nv-accent);
  cursor: pointer;
  white-space: nowrap;
  border-right: 1px solid var(--nv-glass-border);
}
.cm-td--row:hover { text-decoration: underline; }
.cm-cell {
  width: 18px;
  height: 18px;
  min-width: 18px;
  cursor: pointer;
  transition: opacity var(--nv-duration-fast) var(--nv-ease);
  border: 1px solid transparent;
}
.cm-cell:hover { opacity: 0.7; border-color: var(--nv-text-primary); }
.cm-cell--success { background: var(--nv-success); }
.cm-cell--error { background: var(--nv-error); }
.cm-cell--partial { background: var(--nv-warning); }
.cm-cell--skipped { background: var(--nv-text-tertiary); }
.cm-cell--not_ran { background: var(--nv-glass-bg-light); }
.cm-cell--empty { background: transparent; }
.cm-legend {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 2px;
}
.cm-legend--success { background: var(--nv-success); }
.cm-legend--error { background: var(--nv-error); }
.cm-legend--partial { background: var(--nv-warning); }
.cm-legend--skipped { background: var(--nv-text-tertiary); }
.cm-legend--not_ran { background: var(--nv-glass-bg-light); border: 1px solid var(--nv-glass-border); }
</style>
