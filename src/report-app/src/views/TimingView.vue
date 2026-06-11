<template>
  <div style="min-height: calc(100vh - 88px);">
    <!-- Left Sidebar Navigation -->
    <nav class="nv-sidebar">
      <div class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent timing-nav-header">Navigation</h4>
        <a
          v-for="nav in navItems"
          :key="nav.id"
          :href="`#${nav.id}`"
          :class="['nv-sidebar__link', { 'nv-sidebar__link--active': activeSection === nav.id }]"
          @click.prevent="scrollTo(nav.id)"
        >{{ nav.label }}</a>
      </div>
    </nav>

    <!-- Main Content -->
    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Loading timing data..." />

      <template v-else-if="timing">
        <!-- Executive Summary -->
        <section id="summary">
          <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: 'Timing Analysis' }]" />
          <h2 class="nv-page__title" style="margin: 12px 0 16px;">Timing Analysis</h2>

          <!-- Row 1: 4 stat cards -->
          <div class="nv-grid nv-grid--cards" style="margin-bottom: 12px; grid-template-columns: repeat(4, 1fr);">
            <StatCard label="Total DUTs" :value="timing.per_dut.length" color="purple" />
            <StatCard label="Total Collectors Executed" :value="totalCollectors" color="red" />
            <StatCard label="Completed Successfully" :value="completedSuccessfully" color="blue" />
            <StatCard label="Total Wall-Clock Time" :value="formatDuration(timing.total_duration)" color="green" />
          </div>

          <!-- Row 2: Status cards -->
          <div class="nv-grid nv-grid--cards" style="margin-bottom: 24px; grid-template-columns: repeat(4, 1fr);">
            <StatCard
              label="Passed Collectors"
              :value="statusBreakdown.success"
              :subtitle="`of ${totalCollectors} total`"
              color="emerald"
            />
            <StatCard
              label="Failed Collectors"
              :value="statusBreakdown.error"
              :subtitle="`of ${totalCollectors} total`"
              color="red"
            />
            <StatCard
              label="Partial Collectors"
              :value="statusBreakdown.partial"
              :subtitle="`of ${totalCollectors} total`"
              color="amber"
            />
            <StatCard
              label="Skipped Collectors"
              :value="statusBreakdown.skipped"
              :subtitle="`of ${totalCollectors} total`"
              color="orange"
            />
          </div>
        </section>

        <!-- DUT Performance Chart -->
        <section id="dut-performance" style="margin-bottom: 24px;">
          <div class="nv-chart-card">
            <h4 class="nv-chart-card__title">Per-DUT Performance</h4>
            <ChartFullscreenModal title="Per-DUT Performance">
              <DutPerformanceChart :duts="dutPerformanceData" />
              <template #fullscreen>
                <DutPerformanceChart :duts="dutPerformanceData" />
              </template>
            </ChartFullscreenModal>
          </div>
        </section>

        <!-- Service Charts Row -->
        <section id="service-breakdown" style="margin-bottom: 24px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Service-Level Breakdown</h3>
          <div class="nv-grid nv-grid--charts">
            <div class="nv-chart-card">
              <h4 class="nv-chart-card__title">Collector Distribution by Service</h4>
              <ChartFullscreenModal title="Service Distribution">
                <ServiceDistributionChart :services="timing.per_service" />
                <template #fullscreen>
                  <ServiceDistributionChart :services="timing.per_service" />
                </template>
              </ChartFullscreenModal>
            </div>
            <div class="nv-chart-card">
              <h4 class="nv-chart-card__title">Total Execution Time by Service</h4>
              <ChartFullscreenModal title="Service Time">
                <ServiceTimeChart :services="timing.per_service" />
                <template #fullscreen>
                  <ServiceTimeChart :services="timing.per_service" />
                </template>
              </ChartFullscreenModal>
            </div>
          </div>
        </section>

        <!-- Collector Statistics -->
        <section id="collector-stats" style="margin-bottom: 24px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Collector Duration Statistics</h3>
          <div class="nv-glass" style="padding: 16px 20px;">
            <div style="display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 16px;">
              <div class="timing-stat" v-for="s in durationStats" :key="s.label">
                <span class="timing-stat__label">{{ s.label }}</span>
                <span class="timing-stat__value">{{ s.value }}</span>
              </div>
            </div>
            <div v-if="durationHistogram.length > 0" style="margin-top: 8px;">
              <div class="duration-insights">
                <div>
                  <div class="duration-insights__title">Duration Buckets</div>
                  <div class="duration-buckets">
                    <div
                      v-for="bucket in durationHistogram"
                      :key="bucket.label"
                      class="duration-bucket"
                      :title="`${bucket.label}: ${bucket.count} collectors (${bucket.percent}%)`"
                    >
                      <div class="duration-bucket__bar">
                        <span :style="{ width: bucket.percent + '%' }" />
                      </div>
                      <div class="duration-bucket__meta">
                        <span>{{ bucket.label }}</span>
                        <strong>{{ bucket.count }}</strong>
                        <span>{{ bucket.percent }}%</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div v-if="slowestCollectors.length > 0">
                  <div class="duration-insights__title">Slowest Collectors</div>
                  <div class="slow-collectors">
                    <div v-for="collector in slowestCollectors" :key="`${collector.dutId}:${collector.id}`" class="slow-collector">
                      <div>
                        <strong>{{ collector.id }}</strong>
                        <span>{{ collector.name }}</span>
                      </div>
                      <span>{{ collector.dutId }} / {{ collector.group }}</span>
                      <strong>{{ formatDuration(collector.duration) }}</strong>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- Collector Metric Trends -->
        <section id="collector-trends" style="margin-bottom: 24px;">
          <div class="timing-trend-stack">
            <CollectorMetricTrendCard
              title="Collector Timing"
              y-axis-title="Time"
              top-title="Slowest Collectors"
              unit-label="Duration"
              :items="collectorTimingMetricItems"
              :format-value="formatDuration"
            />
            <CollectorMetricTrendCard
              title="Collector Size"
              y-axis-title="Size"
              top-title="Largest Collectors"
              unit-label="Size"
              :items="collectorSizeMetricItems"
              :format-value="formatBytes"
            />
          </div>
        </section>

        <!-- Coverage Matrix -->
        <section id="coverage-matrix" style="margin-bottom: 24px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Coverage Matrix</h3>
          <div class="nv-glass" style="padding: 16px 20px; overflow-x: auto;">
            <table class="coverage-table">
              <thead>
                <tr>
                  <th style="text-align: left; min-width: 100px;">Service</th>
                  <th v-for="dut in timing.per_dut" :key="dut.dut_id" style="min-width: 60px;">{{ dut.dut_id }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="service in coverageServices" :key="service">
                  <td style="font-weight: 600; font-size: 0.75rem;"><ServiceBadge :service="service" /></td>
                  <td v-for="dut in timing.per_dut" :key="dut.dut_id" style="text-align: center;">
                    <span :class="['coverage-cell', `coverage-cell--${coverageStatus(dut.dut_id, service)}`]">
                      {{ coveragePct(dut.dut_id, service) }}%
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <!-- Execution Timeline (Gantt) -->
        <section id="timeline" style="margin-bottom: 24px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Execution Timeline</h3>
          <div class="nv-chart-card">
            <VerticalExecutionTimeline
              :per-dut="timing.per_dut"
              :total-duration="timing.total_duration"
              max-height="400px"
            />
          </div>
        </section>

        <!-- Error Frequency Chart -->
        <div v-if="manifestStore.errors.length > 0" class="nv-chart-card" style="margin-bottom: 24px;">
          <h4 class="nv-chart-card__title">Top Error Messages</h4>
          <div style="height: 300px;">
            <ChartFullscreenModal title="Top Error Messages">
              <ErrorFrequencyChart :errors="manifestStore.errors" />
              <template #fullscreen>
                <ErrorFrequencyChart :errors="manifestStore.errors" />
              </template>
            </ChartFullscreenModal>
          </div>
        </div>

        <!-- Collector Timing Table -->
        <section id="collector-timing" style="margin-bottom: 24px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Detailed Collector Timing</h3>
          <div class="nv-table-viewport">
            <DataTable
              :columns="collectorColumns"
              :data="collectorTableData"
              :searchable="true"
              :fill-viewport="true"
            >
              <template #cell-status="{ value }">
                <StatusBadge :status="value" />
              </template>
              <template #cell-duration="{ value }">
                {{ formatDuration(value) }}
              </template>
            </DataTable>
          </div>
        </section>

        <!-- Collector Log -->
        <section id="collector-log" style="margin-bottom: 24px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Runtime Output Log</h3>
          <div v-if="runtimeLogPath" class="nv-glass nv-glass--subtle" style="padding: 12px;">
            <router-link :to="`/file/${encodeURIComponent(runtimeLogPath)}`" class="nv-btn nv-btn--primary nv-btn--sm" style="text-decoration: none;">
              Open Full Log Viewer
            </router-link>
          </div>
          <div v-else class="nv-empty nv-glass nv-glass--subtle" style="padding: 12px;">
            No runtime output log found.
          </div>
        </section>
      </template>

      <div v-else class="nv-empty">
        <p>No timing data available.</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import StatCard from '@/components/dashboard/StatCard.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ChartFullscreenModal from '@/components/charts/ChartFullscreenModal.vue'
import DutPerformanceChart from '@/components/charts/DutPerformanceChart.vue'
import ServiceDistributionChart from '@/components/charts/ServiceDistributionChart.vue'
import ServiceTimeChart from '@/components/charts/ServiceTimeChart.vue'
import ErrorFrequencyChart from '@/components/charts/ErrorFrequencyChart.vue'
import VerticalExecutionTimeline from '@/components/charts/VerticalExecutionTimeline.vue'
import CollectorMetricTrendCard, { type CollectorMetricItem } from '@/components/charts/CollectorMetricTrendCard.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import { formatBytes, formatDuration } from '@/utils/format'
import { buildDurationBuckets, normalizeCollectorId, topSlowCollectors } from '@/utils/timing'

interface Column {
  key: string
  label: string
  sortable?: boolean
}

const manifestStore = useManifestStore()
const timing = computed(() => manifestStore.timing)
const activeSection = ref('summary')

const navItems = [
  { id: 'summary', label: 'Executive Summary' },
  { id: 'dut-performance', label: 'Per-DUT Performance' },
  { id: 'service-breakdown', label: 'Service Breakdown' },
  { id: 'collector-stats', label: 'Duration Statistics' },
  { id: 'collector-trends', label: 'Collector Trends' },
  { id: 'coverage-matrix', label: 'Coverage Matrix' },
  { id: 'timeline', label: 'Execution Timeline' },
  { id: 'collector-timing', label: 'Collector Timing' },
  { id: 'collector-log', label: 'Collector Log' },
]

function scrollTo(id: string) {
  const el = document.getElementById(id)
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    activeSection.value = id
  }
}

let observer: IntersectionObserver | null = null

onMounted(() => {
  observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          activeSection.value = entry.target.id
        }
      }
    },
    { rootMargin: '-20% 0px -60% 0px' }
  )
  for (const nav of navItems) {
    const el = document.getElementById(nav.id)
    if (el) observer.observe(el)
  }
})

onUnmounted(() => {
  observer?.disconnect()
})

const totalCollectors = computed(() => {
  if (!timing.value) return 0
  return timing.value.per_dut.reduce((sum, dut) => sum + dut.collectors.length, 0)
})

const statusBreakdown = computed(() => {
  const counts = { success: 0, error: 0, partial: 0, skipped: 0 }
  if (!timing.value) return counts
  for (const dut of timing.value.per_dut) {
    for (const c of dut.collectors) {
      const s = (c.status || '').toLowerCase()
      if (s === 'success' || s === 'complete' || s === 'passed') counts.success++
      else if (s === 'error' || s === 'failed') counts.error++
      else if (s === 'partial') counts.partial++
      else if (s === 'skipped') counts.skipped++
    }
  }
  return counts
})

const completedSuccessfully = computed(() => statusBreakdown.value.success)

const dutPerformanceData = computed(() => {
  if (!timing.value) return []
  return timing.value.per_dut.map(d => ({
    id: d.dut_id,
    duration: d.duration,
    completed: d.collectors.length,
  }))
})

const collectorColumns: Column[] = [
  { key: 'dut_id', label: 'DUT', sortable: true },
  { key: 'name', label: 'Collector', sortable: true },
  { key: 'group', label: 'Service', sortable: true },
  { key: 'status', label: 'Status', sortable: true },
  { key: 'duration', label: 'Duration (s)', sortable: true },
  { key: 'start_time', label: 'Start Time', sortable: true },
  { key: 'end_time', label: 'End Time', sortable: true },
]

const collectorTableData = computed(() => {
  if (!timing.value) return []
  const rows: Array<Record<string, unknown>> = []
  for (const dut of timing.value.per_dut) {
    for (const c of dut.collectors) {
      rows.push({
        dut_id: dut.dut_id,
        id: c.id,
        name: c.name,
        group: c.group,
        status: c.status,
        duration: c.duration,
        start_time: c.start_time || '\u2014',
        end_time: c.end_time || '\u2014',
      })
    }
  }
  return rows.sort((a, b) => (b.duration as number) - (a.duration as number))
})

const runtimeLogPath = computed(() => {
  const logFile = manifestStore.fileIndex.find(f =>
    f.path.endsWith('nvdebug_runtime_output.txt') ||
    f.path.endsWith('.nvdebug_stdout.log')
  )
  return logFile?.path ?? ''
})

// Collector duration statistics
const allDurations = computed(() => {
  if (!timing.value) return []
  const durations: number[] = []
  for (const dut of timing.value.per_dut) {
    for (const c of dut.collectors) {
      if (c.duration > 0) durations.push(c.duration)
    }
  }
  return durations.sort((a, b) => a - b)
})

const allTimedCollectors = computed(() => {
  if (!timing.value) return []
  let index = 0
  return timing.value.per_dut.flatMap(dut =>
    dut.collectors.map(c => ({
      index: ++index,
      id: c.id,
      name: c.name,
      group: displayService(c.group),
      dutId: dut.dut_id,
      duration: c.duration,
    }))
  )
})

const collectorTimingMetricItems = computed<CollectorMetricItem[]>(() => {
  return allTimedCollectors.value.map(collector => ({
    index: collector.index,
    id: collector.id,
    name: collector.name,
    group: collector.group,
    dutId: collector.dutId,
    value: collector.duration,
  }))
})

const collectorSizeByKey = computed(() => {
  const sizes = new Map<string, number>()
  const addSize = (dutId: string, collectorId: string, size: number) => {
    if (!collectorId || size <= 0) return
    const normalizedCollectorId = normalizeCollectorId(collectorId)
    const scopedKey = `${dutId}:${normalizedCollectorId}`
    sizes.set(scopedKey, (sizes.get(scopedKey) ?? 0) + size)
    sizes.set(normalizedCollectorId, (sizes.get(normalizedCollectorId) ?? 0) + size)
  }

  for (const file of manifestStore.fileIndex) {
    addSize(file.dut_id, file.collector_id, Number(file.size) || 0)
  }

  for (const dut of manifestStore.duts) {
    for (const group of dut.collector_groups ?? []) {
      for (const collector of group.collectors ?? []) {
        for (const file of collector.files ?? []) {
          addSize(dut.id, collector.id, Number(file.size) || 0)
        }
      }
    }
  }

  return sizes
})

const collectorSizeMetricItems = computed<CollectorMetricItem[]>(() => {
  return allTimedCollectors.value.map(collector => ({
    index: collector.index,
    id: collector.id,
    name: collector.name,
    group: collector.group,
    dutId: collector.dutId,
    value: collectorSizeByKey.value.get(`${collector.dutId}:${normalizeCollectorId(collector.id)}`)
      ?? collectorSizeByKey.value.get(normalizeCollectorId(collector.id))
      ?? 0,
  }))
})

function percentile(arr: number[], p: number): number {
  if (arr.length === 0) return 0
  const idx = (p / 100) * (arr.length - 1)
  const lo = Math.floor(idx)
  const hi = Math.ceil(idx)
  if (lo === hi) return arr[lo]
  return arr[lo] + (arr[hi] - arr[lo]) * (idx - lo)
}

const durationStats = computed(() => {
  const d = allDurations.value
  if (d.length === 0) return []
  const sum = d.reduce((a, b) => a + b, 0)
  return [
    { label: 'Min', value: formatDuration(d[0]) },
    { label: 'Median', value: formatDuration(d[Math.floor(d.length / 2)]) },
    { label: 'Mean', value: formatDuration(sum / d.length) },
    { label: 'P95', value: formatDuration(percentile(d, 95)) },
    { label: 'P99', value: formatDuration(percentile(d, 99)) },
    { label: 'Max', value: formatDuration(d[d.length - 1]) },
  ]
})

const durationHistogram = computed(() => {
  return buildDurationBuckets(allDurations.value)
})

const slowestCollectors = computed(() => {
  return topSlowCollectors(allTimedCollectors.value, 5)
})

// Coverage matrix
const coverageServices = computed(() => {
  if (!timing.value) return []
  const services = new Set<string>()
  for (const dut of timing.value.per_dut) {
    for (const c of dut.collectors) {
      services.add(c.group)
    }
  }
  return [...services].sort()
})

function coveragePct(dutId: string, service: string): number {
  if (!timing.value) return 0
  const dut = timing.value.per_dut.find(d => d.dut_id === dutId)
  if (!dut) return 0
  const collectors = dut.collectors.filter(c => c.group === service)
  if (collectors.length === 0) return 0
  const succeeded = collectors.filter(c => c.status === 'success' || c.status === 'complete' || c.status === 'passed').length
  return Math.round((succeeded / collectors.length) * 100)
}

function coverageStatus(dutId: string, service: string): string {
  const pct = coveragePct(dutId, service)
  if (pct >= 100) return 'full'
  if (pct >= 80) return 'high'
  if (pct >= 50) return 'medium'
  if (pct > 0) return 'low'
  return 'none'
}

function displayService(service: string): string {
  return service
    .replace(/_/g, ' ')
    .replace(/\b\w/g, letter => letter.toUpperCase())
}

</script>

<style scoped>
.timing-nav-header {
  padding: 4px 8px;
  border-radius: var(--nv-radius-sm);
  margin-bottom: 8px;
}

.timing-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 8px 6px;
  background: var(--nv-glass-bg-light);
  border-radius: var(--nv-radius-md);
  border: 1px solid var(--nv-glass-border);
}
.timing-stat__label {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--nv-text-tertiary);
  font-weight: 600;
}
.timing-stat__value {
  font-size: 1rem;
  font-weight: 700;
  color: var(--nv-text-primary);
  font-family: var(--nv-font-mono);
}

.timing-trend-stack {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.duration-insights {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(280px, 0.8fr);
  gap: 16px;
  margin-top: 8px;
}

.duration-insights__title {
  margin-bottom: 8px;
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
  font-weight: 700;
}

.duration-buckets,
.slow-collectors {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.duration-bucket {
  display: grid;
  grid-template-columns: minmax(120px, 1fr) 150px;
  gap: 10px;
  align-items: center;
}

.duration-bucket__bar {
  height: 10px;
  overflow: hidden;
  border-radius: var(--nv-radius-full);
  background: var(--nv-bg-tertiary);
}

.duration-bucket__bar span {
  display: block;
  height: 100%;
  min-width: 2px;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--nv-accent-bold), var(--nv-accent));
}

.duration-bucket__meta,
.slow-collector {
  display: grid;
  grid-template-columns: 64px 42px 42px;
  gap: 8px;
  align-items: center;
  color: var(--nv-text-secondary);
  font-size: 0.6875rem;
}

.duration-bucket__meta strong,
.slow-collector strong {
  color: var(--nv-text-primary);
  font-family: var(--nv-font-mono);
}

.slow-collector {
  grid-template-columns: minmax(0, 1fr) minmax(90px, auto) auto;
  padding: 6px 8px;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-sm);
  background: var(--nv-glass-bg-light);
}

.slow-collector div {
  display: flex;
  min-width: 0;
  gap: 6px;
}

.slow-collector div span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.coverage-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.75rem;
}
.coverage-table th, .coverage-table td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--nv-glass-border);
}
.coverage-table th {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--nv-text-secondary);
  text-align: center;
}
.coverage-cell {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 0.6875rem;
  font-weight: 600;
  font-family: var(--nv-font-mono);
}
.coverage-cell--full { background: var(--nv-success-muted); color: var(--nv-success); }
.coverage-cell--high { background: rgba(118, 185, 0, 0.1); color: var(--nv-accent); }
.coverage-cell--medium { background: var(--nv-warning-muted); color: var(--nv-warning); }
.coverage-cell--low { background: var(--nv-error-muted); color: var(--nv-error); }
.coverage-cell--none { background: rgba(100, 116, 139, 0.06); color: var(--nv-text-tertiary); }

@media (max-width: 1100px) {
  .duration-insights {
    grid-template-columns: 1fr;
  }
}
</style>
