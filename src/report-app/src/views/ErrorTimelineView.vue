<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 0; font-size: 0.6875rem;">Filter by DUT</h4>
      <div style="padding: 4px 0; max-height: 200px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !dutFilter }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = ''"
        >All DUTs</a>
        <a
          v-for="d in dutOptions"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': dutFilter === d.id }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="dutFilter = d.id"
        >
          <span>{{ d.id }}</span>
          <span class="nv-badge nv-badge--error" style="font-size: 0.625rem;">{{ d.count }}</span>
        </a>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Filter by Service</h4>
      <div style="padding: 4px 0;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !serviceFilter }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="serviceFilter = ''"
        >All Services</a>
        <a
          v-for="s in serviceOptions"
          :key="s"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': serviceFilter === s }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="serviceFilter = s"
        >{{ s }}</a>
      </div>
    </div>

    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Building error timeline..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Error Timeline' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 8px;">Error Timeline</h2>

        <div v-if="!hasTimestamps" class="nv-glass" style="padding: 16px; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <p style="font-size: 0.75rem; color: var(--nv-warning); margin: 0;">
            <strong>Note:</strong> {{ noTimestampCount }} of {{ filteredErrors.length }} errors have no timestamp. They appear at the end of the list below.
          </p>
        </div>

        <!-- Timeline visualization -->
        <div v-if="timedErrors.length > 0" class="et-timeline nv-glass" style="padding: 16px; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <h3 class="nv-section-title" style="margin: 0 0 12px; font-size: 0.8125rem;">
            Error Density
            <span style="font-size: 0.6875rem; font-weight: 400; color: var(--nv-text-tertiary); margin-left: 6px;">
              {{ formatTime(timeRange.min) }} — {{ formatTime(timeRange.max) }}
            </span>
          </h3>
          <div class="et-density">
            <div
              v-for="(bucket, i) in densityBuckets"
              :key="i"
              class="et-density__bar"
              :style="{ height: bucket.pct + '%' }"
              :class="{ 'et-density__bar--active': brushRange && i >= brushRange[0] && i <= brushRange[1] }"
              :title="`${bucket.count} errors at ${bucket.label}`"
              @click="toggleBrush(i)"
            ></div>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 0.5625rem; color: var(--nv-text-tertiary); margin-top: 4px;">
            <span>{{ formatTime(timeRange.min) }}</span>
            <span>{{ formatTime(timeRange.max) }}</span>
          </div>
        </div>

        <!-- Error list -->
        <div class="nv-card">
          <DataTable
            :columns="columns"
            :data="displayErrors"
            :searchable="true"
            :fill-viewport="true"
            @row-click="(row: Record<string, any>) => router.push(`/dut/${encodeURIComponent(row.dut_id)}/${encodeURIComponent(row.collector_group)}/${encodeURIComponent(row.collector_id)}`)"
          >
            <template #cell-collector_group="{ value }">
              <ServiceBadge :service="value" />
            </template>
          </DataTable>
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

const router = useRouter()
const manifestStore = useManifestStore()
const dutFilter = ref('')
const serviceFilter = ref('')
const brushRange = ref<[number, number] | null>(null)

const BUCKET_COUNT = 40

const dutOptions = computed(() => {
  const counts = new Map<string, number>()
  for (const e of manifestStore.errors) {
    counts.set(e.dut_id, (counts.get(e.dut_id) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count)
})

const serviceOptions = computed(() => {
  const set = new Set<string>()
  for (const e of manifestStore.errors) set.add(e.collector_group)
  return [...set].sort()
})

const filteredErrors = computed(() => {
  let errs = manifestStore.errors
  if (dutFilter.value) errs = errs.filter(e => e.dut_id === dutFilter.value)
  if (serviceFilter.value) errs = errs.filter(e => e.collector_group === serviceFilter.value)
  return errs
})

const timedErrors = computed(() =>
  filteredErrors.value
    .filter(e => e.timestamp)
    .map(e => ({ ...e, ts: new Date(e.timestamp!).getTime() }))
    .filter(e => !isNaN(e.ts))
    .sort((a, b) => a.ts - b.ts)
)

const hasTimestamps = computed(() => timedErrors.value.length === filteredErrors.value.length)
const noTimestampCount = computed(() => filteredErrors.value.length - timedErrors.value.length)

const timeRange = computed(() => {
  if (timedErrors.value.length === 0) return { min: 0, max: 0 }
  return { min: timedErrors.value[0].ts, max: timedErrors.value[timedErrors.value.length - 1].ts }
})

const densityBuckets = computed(() => {
  const { min, max } = timeRange.value
  if (max <= min) return []
  const step = (max - min) / BUCKET_COUNT
  const buckets = Array.from({ length: BUCKET_COUNT }, (_, i) => ({
    count: 0,
    label: formatTime(min + i * step),
    pct: 0,
  }))
  for (const e of timedErrors.value) {
    const idx = Math.min(Math.floor((e.ts - min) / step), BUCKET_COUNT - 1)
    buckets[idx].count++
  }
  const maxCount = Math.max(...buckets.map(b => b.count), 1)
  for (const b of buckets) b.pct = (b.count / maxCount) * 100
  return buckets
})

function toggleBrush(i: number) {
  if (brushRange.value && brushRange.value[0] === i && brushRange.value[1] === i) {
    brushRange.value = null
  } else {
    brushRange.value = [i, i]
  }
}

const displayErrors = computed(() => {
  let errs = filteredErrors.value.map(e => ({
    ...e,
    timestamp: e.timestamp || '—',
  }))

  if (brushRange.value && timedErrors.value.length > 0) {
    const { min, max } = timeRange.value
    const step = (max - min) / BUCKET_COUNT
    const lo = min + brushRange.value[0] * step
    const hi = min + (brushRange.value[1] + 1) * step
    errs = errs.filter(e => {
      if (!e.timestamp || e.timestamp === '—') return false
      const ts = new Date(e.timestamp).getTime()
      return ts >= lo && ts <= hi
    })
  }

  return errs.sort((a, b) => {
    if (a.timestamp === '—' && b.timestamp === '—') return 0
    if (a.timestamp === '—') return 1
    if (b.timestamp === '—') return -1
    return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  })
})

const columns = [
  { key: 'timestamp', label: 'Time', sortable: true },
  { key: 'dut_id', label: 'DUT', sortable: true },
  { key: 'collector_group', label: 'Service', sortable: true },
  { key: 'collector_id', label: 'Collector', sortable: true },
  { key: 'message', label: 'Error Message', sortable: true },
]

function formatTime(ts: number): string {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
</script>

<style scoped>
.et-density {
  display: flex;
  align-items: flex-end;
  gap: 1px;
  height: 60px;
}
.et-density__bar {
  flex: 1;
  background: var(--nv-error);
  opacity: 0.5;
  border-radius: 1px 1px 0 0;
  min-height: 2px;
  cursor: pointer;
  transition: opacity var(--nv-duration-fast) var(--nv-ease);
}
.et-density__bar:hover { opacity: 0.8; }
.et-density__bar--active { opacity: 1; }
</style>
