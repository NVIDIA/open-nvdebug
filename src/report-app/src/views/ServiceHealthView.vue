<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 0; font-size: 0.6875rem;">Services</h4>
      <div style="padding: 4px 0;">
        <a
          v-for="s in serviceList"
          :key="s.name"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': selectedService === s.name }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="selectedService = selectedService === s.name ? '' : s.name"
        >
          <span>{{ s.name }}</span>
          <span class="nv-badge" :class="s.successRate >= 90 ? 'nv-badge--success' : s.successRate >= 50 ? 'nv-badge--warning' : 'nv-badge--error'" style="font-size: 0.625rem;">{{ s.successRate.toFixed(0) }}%</span>
        </a>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Filter by DUT</h4>
      <div style="padding: 4px 0; max-height: 200px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !dutFilter }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = ''"
        >All DUTs</a>
        <a
          v-for="d in manifestStore.duts"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': dutFilter === d.id }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = d.id"
        >{{ d.id }}</a>
      </div>
    </div>

    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Analyzing service health..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Service Health' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">Service Health Summary</h2>

        <div class="sh-cards">
          <div v-for="s in displayServices" :key="s.name" class="sh-card nv-glass" @click="selectedService = selectedService === s.name ? '' : s.name">
            <div class="sh-card__header">
              <ServiceBadge :service="s.name" />
              <span class="sh-card__rate" :style="{ color: s.successRate >= 90 ? 'var(--nv-success)' : s.successRate >= 50 ? 'var(--nv-warning)' : 'var(--nv-error)' }">{{ s.successRate.toFixed(1) }}%</span>
            </div>
            <div class="sh-card__stats">
              <span style="color: var(--nv-success);">{{ s.success }} ok</span>
              <span v-if="s.error" style="color: var(--nv-error);">{{ s.error }} err</span>
              <span v-if="s.partial" style="color: var(--nv-warning);">{{ s.partial }} partial</span>
              <span v-if="s.skipped" style="color: var(--nv-text-tertiary);">{{ s.skipped }} skip</span>
            </div>
            <div class="sh-card__bar">
              <div class="sh-card__bar-fill sh-card__bar-fill--success" :style="{ width: pct(s.success, s.total) }"></div>
              <div class="sh-card__bar-fill sh-card__bar-fill--error" :style="{ width: pct(s.error, s.total) }"></div>
              <div class="sh-card__bar-fill sh-card__bar-fill--partial" :style="{ width: pct(s.partial, s.total) }"></div>
            </div>
            <div class="sh-card__meta">
              {{ s.total }} collectors &middot; {{ formatDuration(s.totalDuration) }} total &middot; {{ formatDuration(s.avgDuration) }} avg
            </div>
          </div>
        </div>

        <div v-if="selectedService" style="margin-top: 20px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">{{ selectedService }} — Per-DUT Breakdown</h3>
          <div class="nv-card">
            <DataTable
              :columns="perDutColumns"
              :data="perDutData"
              :searchable="true"
              @row-click="(row: Record<string, any>) => router.push(`/dut/${encodeURIComponent(row.dutId)}`)"
            >
              <template #cell-successRate="{ value }">
                <span :style="{ color: Number(value) >= 90 ? 'var(--nv-success)' : Number(value) >= 50 ? 'var(--nv-warning)' : 'var(--nv-error)', fontWeight: 600 }">{{ Number(value).toFixed(0) }}%</span>
              </template>
            </DataTable>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import DataTable from '@/components/common/DataTable.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import { formatDuration } from '@/utils/format'

const router = useRouter()
const manifestStore = useManifestStore()
const selectedService = ref('')
const dutFilter = ref('')

interface ServiceStats {
  name: string
  success: number
  error: number
  partial: number
  skipped: number
  notRan: number
  total: number
  successRate: number
  totalDuration: number
  avgDuration: number
}

const serviceList = computed<ServiceStats[]>(() => {
  const map = new Map<string, ServiceStats>()
  const duts = dutFilter.value ? manifestStore.duts.filter(d => d.id === dutFilter.value) : manifestStore.duts
  for (const dut of duts) {
    for (const g of dut.collector_groups) {
      const svc = g.service_type || g.name
      if (!map.has(svc)) map.set(svc, { name: svc, success: 0, error: 0, partial: 0, skipped: 0, notRan: 0, total: 0, successRate: 0, totalDuration: 0, avgDuration: 0 })
      const s = map.get(svc)!
      for (const c of g.collectors) {
        if (c.status === 'not_ran') { s.notRan++; continue }
        s.total++
        if (c.status === 'success') s.success++
        else if (c.status === 'error') s.error++
        else if (c.status === 'partial') s.partial++
        else if (c.status === 'skipped') s.skipped++
        s.totalDuration += c.execution_time
      }
    }
  }
  for (const s of map.values()) {
    s.successRate = s.total > 0 ? (s.success / s.total) * 100 : 0
    s.avgDuration = s.total > 0 ? s.totalDuration / s.total : 0
  }
  return [...map.values()].sort((a, b) => b.total - a.total)
})

const displayServices = computed(() => serviceList.value)

const perDutColumns = [
  { key: 'dutId', label: 'DUT', sortable: true },
  { key: 'success', label: 'Success', sortable: true },
  { key: 'error', label: 'Error', sortable: true },
  { key: 'partial', label: 'Partial', sortable: true },
  { key: 'total', label: 'Total', sortable: true },
  { key: 'successRate', label: 'Success Rate', sortable: true },
  { key: 'totalDuration', label: 'Duration', sortable: true },
]

const perDutData = computed(() => {
  if (!selectedService.value) return []
  const rows: Record<string, any>[] = []
  const duts = dutFilter.value ? manifestStore.duts.filter(d => d.id === dutFilter.value) : manifestStore.duts
  for (const dut of duts) {
    let success = 0, error = 0, partial = 0, total = 0, dur = 0
    for (const g of dut.collector_groups) {
      if ((g.service_type || g.name) !== selectedService.value) continue
      for (const c of g.collectors) {
        if (c.status === 'not_ran') continue
        total++
        if (c.status === 'success') success++
        else if (c.status === 'error') error++
        else if (c.status === 'partial') partial++
        dur += c.execution_time
      }
    }
    if (total > 0) {
      rows.push({
        dutId: dut.id,
        success,
        error,
        partial,
        total,
        successRate: ((success / total) * 100).toFixed(1),
        totalDuration: formatDuration(dur),
      })
    }
  }
  return rows
})

function pct(n: number, total: number) {
  return total > 0 ? `${(n / total) * 100}%` : '0%'
}

</script>

<style scoped>
.sh-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.sh-card {
  padding: 14px 16px;
  border-radius: var(--nv-radius-lg);
  cursor: pointer;
  transition: box-shadow var(--nv-duration-base) var(--nv-ease), transform var(--nv-duration-base) var(--nv-ease);
}
.sh-card:hover {
  box-shadow: var(--nv-glass-shadow);
  transform: translateY(-1px);
}
.sh-card__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.sh-card__rate {
  font-size: 1.25rem;
  font-weight: 700;
  font-family: var(--nv-font-mono);
}
.sh-card__stats {
  display: flex;
  gap: 8px;
  font-size: 0.6875rem;
  font-weight: 600;
  margin-bottom: 8px;
}
.sh-card__bar {
  height: 4px;
  border-radius: 2px;
  background: var(--nv-glass-bg-light);
  display: flex;
  overflow: hidden;
  margin-bottom: 6px;
}
.sh-card__bar-fill { height: 100%; }
.sh-card__bar-fill--success { background: var(--nv-success); }
.sh-card__bar-fill--error { background: var(--nv-error); }
.sh-card__bar-fill--partial { background: var(--nv-warning); }
.sh-card__meta {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
}
</style>
