<template>
  <div style="min-height: calc(100vh - 88px);">
    <!-- Sidebar -->
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 0; font-size: 0.6875rem;">Summary</h4>
      <div style="padding: 8px 12px; display: flex; flex-direction: column; gap: 4px;">
        <div v-for="sev in (['critical', 'warning', 'info'] as const)" :key="sev" style="display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: var(--nv-text-secondary);">
          <span :class="['ano-sev-dot', `ano-sev-dot--${sev}`]"></span>
          <span style="text-transform: capitalize;">{{ sev }}</span>
          <span style="margin-left: auto; font-family: var(--nv-font-mono); font-size: 0.6875rem; color: var(--nv-text-tertiary);">{{ summary[sev] }}</span>
        </div>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Severity</h4>
      <div style="padding: 4px 0;">
        <a
          v-for="sev in (['all', 'critical', 'warning', 'info'] as const)"
          :key="sev"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': severityFilter === sev }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="severityFilter = sev"
        >
          <span style="text-transform: capitalize;">{{ sev === 'all' ? 'All Severities' : sev }}</span>
          <span class="nv-badge nv-badge--neutral" style="font-size: 0.625rem;">{{ sev === 'all' ? anomalies.length : summary[sev] }}</span>
        </a>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Type</h4>
      <div style="padding: 4px 0;">
        <a
          v-for="t in typeOptions"
          :key="t.key"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': typeFilter === t.key }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="typeFilter = t.key"
        >
          <span>{{ t.label }}</span>
          <span class="nv-badge nv-badge--neutral" style="font-size: 0.625rem;">{{ t.count }}</span>
        </a>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">DUT</h4>
      <div style="padding: 4px 0; max-height: 200px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !dutFilter }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="dutFilter = ''"
        >
          <span>All DUTs</span>
          <span class="nv-badge nv-badge--neutral" style="font-size: 0.625rem;">{{ anomalies.length }}</span>
        </a>
        <a
          v-for="d in dutOptions"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': dutFilter === d.id }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="dutFilter = d.id"
        >
          <span>{{ d.id }}</span>
          <span class="nv-badge" :class="d.count > 0 ? 'nv-badge--warning' : 'nv-badge--neutral'" style="font-size: 0.625rem;">{{ d.count }}</span>
        </a>
      </div>
    </div>

    <!-- Main Content -->
    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Detecting anomalies..." />

      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Anomalies' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">
          Anomalies
          <span v-if="filtered.length" style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary); margin-left: 6px;">{{ filtered.length }} detected</span>
        </h2>

        <!-- Severity badges row -->
        <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px;">
          <span class="ano-pill ano-pill--critical">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            {{ summary.critical }} critical
          </span>
          <span class="ano-pill ano-pill--warning">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            {{ summary.warning }} warning
          </span>
          <span class="ano-pill ano-pill--info">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
            {{ summary.info }} info
          </span>
        </div>

        <!-- Empty state -->
        <div v-if="anomalies.length === 0" class="nv-glass" style="padding: 48px 32px; text-align: center; border-radius: var(--nv-radius-lg);">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--nv-success)" stroke-width="1.5" stroke-linecap="round" style="margin-bottom: 12px;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <h3 style="font-size: 1rem; font-weight: 700; color: var(--nv-text-primary); margin: 0 0 4px;">No Anomalies Detected</h3>
          <p style="font-size: 0.8125rem; color: var(--nv-text-secondary); margin: 0; max-width: 400px; margin-inline: auto; line-height: 1.5;">
            Statistical analysis found no significant outliers in execution times, failure rates, log sizes, or cross-DUT consistency.
          </p>
        </div>

        <!-- Filtered empty -->
        <div v-else-if="filtered.length === 0" class="nv-glass" style="padding: 32px; text-align: center; border-radius: var(--nv-radius-lg);">
          <p style="font-size: 0.8125rem; color: var(--nv-text-secondary); margin: 0;">No anomalies match the current filters.</p>
          <button class="nv-btn nv-btn--ghost" style="margin-top: 12px; font-size: 0.75rem;" @click="severityFilter = 'all'; typeFilter = 'all'; dutFilter = ''">Clear Filters</button>
        </div>

        <!-- Grouped anomalies -->
        <template v-else>
          <div v-for="group in groupedAnomalies" :key="group.type" class="ano-group">
            <div class="ano-group__header" @click="toggleGroup(group.type)">
              <svg :style="{ transform: expandedGroups.has(group.type) ? 'rotate(90deg)' : '' }" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="transition: transform 0.15s ease; flex-shrink: 0;"><polyline points="9 18 15 12 9 6"/></svg>
              <span class="ano-group__icon">{{ TYPE_META[group.type].icon }}</span>
              <span class="ano-group__title">{{ TYPE_META[group.type].label }}</span>
              <span class="nv-badge nv-badge--neutral" style="font-size: 0.625rem;">{{ group.items.length }}</span>
              <span class="ano-group__desc">{{ TYPE_META[group.type].desc }}</span>
            </div>

            <div v-if="expandedGroups.has(group.type)" class="ano-group__body">
              <div
                v-for="a in group.items"
                :key="a.id"
                class="ano-card nv-glass"
                :class="`ano-card--${a.severity}`"
              >
                <div class="ano-card__header">
                  <span :class="['ano-sev-dot', `ano-sev-dot--${a.severity}`]"></span>
                  <span class="ano-card__sev">{{ a.severity }}</span>
                  <span class="ano-card__title">{{ a.title }}</span>
                  <span v-if="a.collectorId" class="ano-card__cid">{{ a.collectorId }}</span>
                </div>
                <p class="ano-card__desc">{{ a.description }}</p>
                <div class="ano-card__meta">
                  <span class="ano-card__dut" @click.stop="router.push(`/dut/${encodeURIComponent(a.dutId)}`)">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    {{ a.dutId }}
                  </span>
                  <span v-if="a.collectorId" class="ano-card__collector" @click.stop="goToCollector(a)">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    {{ a.collectorId }}
                  </span>
                  <span class="ano-card__stat">
                    Value: <strong>{{ formatValue(a) }}</strong>
                  </span>
                  <span class="ano-card__stat">
                    Threshold: <strong>{{ formatThreshold(a) }}</strong>
                  </span>
                </div>
              </div>
            </div>
          </div>
        </template>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { detectAnomalies, getAnomalySummary } from '@/composables/useAnomalyDetection'
import type { Anomaly, AnomalyType } from '@/composables/useAnomalyDetection'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const router = useRouter()
const manifestStore = useManifestStore()

const severityFilter = ref<'all' | 'critical' | 'warning' | 'info'>('all')
const typeFilter = ref<string>('all')
const dutFilter = ref('')

const TYPE_META: Record<AnomalyType, { label: string; icon: string; desc: string }> = {
  cross_dut_slow: {
    label: 'Cross-DUT Slow Collectors',
    icon: '⏱',
    desc: 'Same collector ran significantly slower on specific DUTs compared to the fleet median.',
  },
  slow_collector: {
    label: 'Locally Slow Collectors',
    icon: '🐢',
    desc: 'Collectors that are slow relative to other collectors on the same DUT.',
  },
  high_failure_rate: {
    label: 'High Failure Rate',
    icon: '🔴',
    desc: 'DUTs where a high percentage of collectors failed.',
  },
  missing_files: {
    label: 'Missing Output Files',
    icon: '📁',
    desc: 'Collectors that completed but produced no output files.',
  },
  abnormal_log_size: {
    label: 'Abnormal Log Size',
    icon: '📊',
    desc: 'DUTs with log sizes significantly different from the fleet median.',
  },
  cross_dut_inconsistency: {
    label: 'Cross-DUT Inconsistencies',
    icon: '⚡',
    desc: 'Collectors that fail on some DUTs but succeed on others.',
  },
  execution_gap: {
    label: 'Execution Gaps',
    icon: '⏸',
    desc: 'Large idle periods between consecutive collector runs on a DUT.',
  },
}

const anomalies = computed<Anomaly[]>(() =>
  manifestStore.manifest ? detectAnomalies(manifestStore.manifest) : []
)

const summary = computed(() => getAnomalySummary(anomalies.value))

const filtered = computed(() => {
  let list = anomalies.value
  if (severityFilter.value !== 'all') {
    list = list.filter(a => a.severity === severityFilter.value)
  }
  if (typeFilter.value !== 'all') {
    list = list.filter(a => a.type === typeFilter.value)
  }
  if (dutFilter.value) {
    list = list.filter(a => a.dutId === dutFilter.value)
  }
  return list
})

const typeOptions = computed(() => {
  const counts = new Map<string, number>()
  for (const a of anomalies.value) {
    counts.set(a.type, (counts.get(a.type) ?? 0) + 1)
  }
  const opts = [{ key: 'all', label: 'All Types', count: anomalies.value.length }]
  for (const [key, meta] of Object.entries(TYPE_META)) {
    const c = counts.get(key) ?? 0
    if (c > 0) opts.push({ key, label: meta.label, count: c })
  }
  return opts
})

const dutOptions = computed(() => {
  const counts = new Map<string, number>()
  for (const a of anomalies.value) {
    counts.set(a.dutId, (counts.get(a.dutId) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
})

interface AnomalyGroup {
  type: AnomalyType
  items: Anomaly[]
}

const expandedGroups = ref(new Set<string>())

const groupedAnomalies = computed<AnomalyGroup[]>(() => {
  const groups = new Map<AnomalyType, Anomaly[]>()
  for (const a of filtered.value) {
    if (!groups.has(a.type)) groups.set(a.type, [])
    groups.get(a.type)!.push(a)
  }
  const typeOrder: AnomalyType[] = [
    'high_failure_rate',
    'cross_dut_slow',
    'cross_dut_inconsistency',
    'missing_files',
    'abnormal_log_size',
    'slow_collector',
  ]
  const result: AnomalyGroup[] = []
  for (const type of typeOrder) {
    const items = groups.get(type)
    if (items?.length) result.push({ type, items })
  }

  if (expandedGroups.value.size === 0 && result.length > 0) {
    expandedGroups.value = new Set(result.map(g => g.type))
  }
  return result
})

function toggleGroup(type: string) {
  const next = new Set(expandedGroups.value)
  if (next.has(type)) next.delete(type)
  else next.add(type)
  expandedGroups.value = next
}

function goToCollector(a: Anomaly) {
  if (!a.collectorId || !a.dutId) return
  const dut = manifestStore.duts.find(d => d.id === a.dutId)
  if (!dut) return
  for (const g of dut.collector_groups) {
    const found = g.collectors.find(c => c.id === a.collectorId)
    if (found) {
      router.push(`/dut/${encodeURIComponent(a.dutId)}/${encodeURIComponent(g.name)}/${encodeURIComponent(a.collectorId)}`)
      return
    }
  }
  router.push(`/dut/${encodeURIComponent(a.dutId)}`)
}

function formatValue(a: Anomaly): string {
  if (a.type === 'high_failure_rate') return `${a.value.toFixed(0)}%`
  if (a.type === 'abnormal_log_size') return formatBytes(a.value)
  if (a.type === 'missing_files') return '0 files'
  return `${a.value.toFixed(1)}s`
}

function formatThreshold(a: Anomaly): string {
  if (a.type === 'high_failure_rate') return `${a.threshold.toFixed(0)}%`
  if (a.type === 'abnormal_log_size') return formatBytes(a.threshold)
  if (a.type === 'missing_files') return '≥ 1 file'
  return `${a.threshold.toFixed(1)}s`
}

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}
</script>

<style scoped>
.ano-sev-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.ano-sev-dot--critical { background: var(--nv-error); }
.ano-sev-dot--warning { background: var(--nv-warning); }
.ano-sev-dot--info { background: var(--nv-info); }

.ano-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 10px;
  font-weight: 600;
  font-size: 0.75rem;
}
.ano-pill--critical { background: var(--nv-error-muted); color: var(--nv-error); }
.ano-pill--warning { background: var(--nv-warning-muted); color: var(--nv-warning); }
.ano-pill--info { background: var(--nv-info-muted); color: var(--nv-info); }

.ano-group {
  margin-bottom: 12px;
}
.ano-group__header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  cursor: pointer;
  border-radius: var(--nv-radius-md);
  transition: background var(--nv-duration-base) var(--nv-ease);
}
.ano-group__header:hover {
  background: var(--nv-glass-bg-light);
}
.ano-group__icon {
  font-size: 1rem;
  flex-shrink: 0;
}
.ano-group__title {
  font-size: 0.875rem;
  font-weight: 700;
  color: var(--nv-text-primary);
}
.ano-group__desc {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  margin-left: auto;
  text-align: right;
  max-width: 400px;
}
.ano-group__body {
  padding: 4px 0 4px 20px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.ano-card {
  border-radius: var(--nv-radius-lg);
  padding: 12px 16px;
  transition: box-shadow var(--nv-duration-base) var(--nv-ease);
}
.ano-card:hover {
  box-shadow: var(--nv-glass-shadow);
}
.ano-card--critical { border-left: 3px solid var(--nv-error); }
.ano-card--warning { border-left: 3px solid var(--nv-warning); }
.ano-card--info { border-left: 3px solid var(--nv-info); }

.ano-card__header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.ano-card__sev {
  font-size: 0.625rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  flex-shrink: 0;
}
.ano-card--critical .ano-card__sev { color: var(--nv-error); }
.ano-card--warning .ano-card__sev { color: var(--nv-warning); }
.ano-card--info .ano-card__sev { color: var(--nv-info); }

.ano-card__title {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--nv-text-primary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ano-card__cid {
  font-family: var(--nv-font-mono);
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
}

.ano-card__desc {
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  line-height: 1.5;
  margin: 0 0 8px;
}

.ano-card__meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 0.6875rem;
}
.ano-card__dut,
.ano-card__collector {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--nv-accent);
  font-weight: 600;
  cursor: pointer;
  transition: opacity var(--nv-duration-base) var(--nv-ease);
}
.ano-card__dut:hover,
.ano-card__collector:hover {
  opacity: 0.7;
}
.ano-card__stat {
  color: var(--nv-text-tertiary);
}
.ano-card__stat strong {
  font-family: var(--nv-font-mono);
  color: var(--nv-text-secondary);
}

@media (max-width: 768px) {
  .ano-group__desc { display: none; }
}
</style>
