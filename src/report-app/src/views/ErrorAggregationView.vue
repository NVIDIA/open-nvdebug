<template>
  <div style="min-height: calc(100vh - 88px);">
    <!-- Sidebar -->
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 0; font-size: 0.6875rem;">Severity</h4>
      <div style="padding: 6px 12px; display: flex; flex-direction: column; gap: 2px;">
        <div v-for="sev in ['critical', 'high', 'medium', 'low']" :key="sev" style="display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: var(--nv-text-secondary);">
          <span :class="['ea-sev-dot', `ea-sev-dot--${sev}`]"></span>
          <span>{{ sev }}</span>
          <span style="margin-left: auto; font-family: var(--nv-font-mono); font-size: 0.6875rem; color: var(--nv-text-tertiary);">{{ severityCounts[sev as keyof typeof severityCounts] }}</span>
        </div>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Filter by DUT</h4>
      <div style="padding: 4px 0;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !dutFilter }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="dutFilter = ''"
        >
          <span>All DUTs</span>
          <span class="nv-badge nv-badge--neutral" style="font-size: 0.625rem;">{{ manifestStore.errors.length }}</span>
        </a>
        <a
          v-for="dut in dutErrorCounts"
          :key="dut.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': dutFilter === dut.id }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="dutFilter = dut.id"
        >
          <span>{{ dut.id }}</span>
          <span class="nv-badge" :class="dut.count > 0 ? 'nv-badge--error' : 'nv-badge--neutral'" style="font-size: 0.625rem;">{{ dut.count }}</span>
        </a>
      </div>
    </div>

    <!-- Main Content -->
    <div class="nv-page" style="margin-left: 260px;">
      <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Error Aggregation' }]" />

      <h2 class="nv-page__title" style="margin: 16px 0 20px;">
        {{ dutFilter ? `${dutFilter} Errors` : 'All Errors' }} ({{ filteredErrors.length }})
      </h2>

      <!-- View toggle -->
      <div class="nv-toggle-group" style="margin-bottom: 12px;">
        <button @click="viewMode = 'clustered'" :class="['nv-toggle-group__btn', { 'nv-toggle-group__btn--active': viewMode === 'clustered' }]">Clustered</button>
        <button @click="viewMode = 'table'" :class="['nv-toggle-group__btn', { 'nv-toggle-group__btn--active': viewMode === 'table' }]">All Errors</button>
      </div>

      <!-- Cluster summary -->
      <div v-if="viewMode === 'clustered'" style="margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; font-size: 0.75rem;">
        <span class="ea-sev-badge ea-sev-badge--critical">{{ severityCounts.critical }} critical</span>
        <span class="ea-sev-badge ea-sev-badge--high">{{ severityCounts.high }} high</span>
        <span class="ea-sev-badge ea-sev-badge--medium">{{ severityCounts.medium }} medium</span>
        <span class="ea-sev-badge ea-sev-badge--low">{{ severityCounts.low }} low</span>
        <span style="color: var(--nv-text-secondary); margin-left: 8px;">{{ clusters.length }} clusters from {{ filteredErrors.length }} errors</span>
      </div>

      <!-- Clustered view -->
      <div v-if="viewMode === 'clustered'">
        <div v-if="clusters.length === 0" class="ea-empty-state nv-glass" style="border-radius: 12px;">
          <div class="ea-empty-state__icon">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--nv-success)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
          </div>
          <h3 class="ea-empty-state__title">
            {{ dutFilter ? `No errors for ${dutFilter}` : 'No errors found in this collection' }}
          </h3>
          <p class="ea-empty-state__desc">
            {{ emptyStateExplanation }}
          </p>
          <div class="ea-empty-state__breakdown">
            <div class="ea-empty-state__stat">
              <span class="ea-empty-state__stat-value" style="color: var(--nv-success);">{{ collectionBreakdown.success }}</span>
              <span class="ea-empty-state__stat-label">Passed</span>
            </div>
            <div class="ea-empty-state__stat">
              <span class="ea-empty-state__stat-value" style="color: var(--nv-warning);">{{ collectionBreakdown.partial }}</span>
              <span class="ea-empty-state__stat-label">Partial</span>
            </div>
            <div class="ea-empty-state__stat">
              <span class="ea-empty-state__stat-value" style="color: var(--nv-skipped, var(--nv-text-tertiary));">{{ collectionBreakdown.skipped }}</span>
              <span class="ea-empty-state__stat-label">Skipped</span>
            </div>
            <div class="ea-empty-state__stat">
              <span class="ea-empty-state__stat-value" style="color: var(--nv-text-tertiary);">{{ collectionBreakdown.notRan }}</span>
              <span class="ea-empty-state__stat-label">Not Ran</span>
            </div>
          </div>
        </div>
        <div v-for="cluster in clusters" :key="cluster.id" class="ea-cluster nv-glass" :class="`ea-cluster--${cluster.severity}`">
          <div class="ea-cluster__header" @click="toggleCluster(cluster.id)">
            <span :class="['ea-sev-dot', `ea-sev-dot--${cluster.severity}`]"></span>
            <span class="ea-cluster__count">{{ cluster.count }}x</span>
            <span class="ea-cluster__msg">{{ cluster.representative.slice(0, 120) }}</span>
            <span v-if="cluster.knownIssue" class="ea-known-tag">Known Issue</span>
            <span class="ea-cluster__duts">{{ cluster.dutIds.length }} DUT{{ cluster.dutIds.length > 1 ? 's' : '' }}</span>
            <span class="ea-cluster__chevron">{{ expandedClusters.has(cluster.id) ? '\u25BC' : '\u25B6' }}</span>
          </div>

          <div v-if="expandedClusters.has(cluster.id)" class="ea-cluster__body">
            <div v-if="cluster.knownIssue" class="ea-known-issue nv-glass--accent">
              <div class="ea-known-issue__title">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="var(--nv-info)" style="flex-shrink: 0;"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5" fill="none"/><path d="M8 5v4M8 11v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                {{ cluster.knownIssue.title }}
              </div>
              <div class="ea-known-issue__desc">{{ cluster.knownIssue.description }}</div>
              <div class="ea-known-issue__fix">
                <strong>Suggested Fix:</strong> {{ cluster.knownIssue.fix }}
              </div>
            </div>

            <div style="margin-bottom: 8px; font-size: 0.75rem; color: var(--nv-text-secondary);">
              <strong>Affected DUTs:</strong> {{ cluster.dutIds.join(', ') }}
            </div>
            <div style="margin-bottom: 8px; font-size: 0.75rem; color: var(--nv-text-secondary);">
              <strong>Collectors:</strong> {{ cluster.collectorIds.join(', ') }}
            </div>

            <div class="ea-cluster__entries">
              <div v-for="(err, i) in cluster.entries" :key="i" class="ea-entry" @click="router.push(`/dut/${err.dut_id}/${err.collector_group}/${err.collector_id}`)">
                <span class="ea-entry__dut">{{ err.dut_id }}</span>
                <span class="ea-entry__cid">{{ err.collector_id }}</span>
                <span class="ea-entry__msg"><ReasonDisplay :text="err.message" :compact="true" /></span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Flat table view -->
      <div v-else class="nv-card">
        <DataTable
          :columns="columns"
          :data="filteredErrors"
          :searchable="true"
          :fill-viewport="true"
          @row-click="(row: Record<string, any>) => router.push(`/dut/${row.dut_id}/${row.collector_group}/${row.collector_id}`)"
        >
          <template #cell-collector_group="{ value }">
            <ServiceBadge :service="value" />
          </template>
          <template #cell-message="{ value }">
            <ReasonDisplay v-if="value" :text="String(value)" :compact="true" />
            <span v-else style="color: var(--nv-text-tertiary);">&mdash;</span>
          </template>
        </DataTable>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import { clusterErrors, type ErrorCluster } from '@/composables/useErrorClustering'

const router = useRouter()
const manifestStore = useManifestStore()

const viewMode = ref<'table' | 'clustered'>('clustered')
const expandedClusters = ref(new Set<number>())
const dutFilter = ref('')

function toggleCluster(id: number) {
  const next = new Set(expandedClusters.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expandedClusters.value = next
}

interface Column { key: string; label: string; sortable?: boolean }
const columns: Column[] = [
  { key: 'dut_id', label: 'DUT', sortable: true },
  { key: 'collector_group', label: 'Group', sortable: true },
  { key: 'collector_id', label: 'Collector ID', sortable: true },
  { key: 'collector_name', label: 'Name', sortable: true },
  { key: 'message', label: 'Error Message', sortable: true },
  { key: 'timestamp', label: 'Timestamp', sortable: true },
]

const dutErrorCounts = computed(() => {
  const counts = new Map<string, number>()
  for (const dut of manifestStore.duts) {
    counts.set(dut.id, 0)
  }
  for (const err of manifestStore.errors) {
    counts.set(err.dut_id, (counts.get(err.dut_id) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([id, count]) => ({ id, count }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
})

const filteredErrors = computed(() => {
  const base = manifestStore.errors.map(e => ({
    ...e,
    timestamp: e.timestamp || '\u2014',
  }))
  if (!dutFilter.value) return base
  return base.filter(e => e.dut_id === dutFilter.value)
})

const clusters = computed<ErrorCluster[]>(() => {
  const source = dutFilter.value
    ? manifestStore.errors.filter(e => e.dut_id === dutFilter.value)
    : manifestStore.errors
  return clusterErrors(source)
})

const severityCounts = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const c of clusters.value) counts[c.severity]++
  return counts
})

const collectionBreakdown = computed(() => {
  const targetDuts = dutFilter.value
    ? manifestStore.duts.filter(d => d.id === dutFilter.value)
    : manifestStore.duts
  let success = 0, partial = 0, skipped = 0, notRan = 0, error = 0
  for (const dut of targetDuts) {
    success += dut.status_summary.success
    partial += dut.status_summary.partial
    skipped += dut.status_summary.skipped
    notRan += dut.status_summary.not_ran ?? 0
    error += dut.status_summary.error
  }
  return { success, partial, skipped, notRan, error, total: success + partial + skipped + error }
})

const emptyStateExplanation = computed(() => {
  const b = collectionBreakdown.value
  if (b.total === 0 && b.notRan > 0) {
    return `All ${b.notRan} collectors were not executed. No errors are expected since nothing ran.`
  }
  if (b.total === 0) {
    return 'No collectors were executed in this collection.'
  }
  if (b.success === b.total) {
    return `All ${b.total} executed collector${b.total > 1 ? 's' : ''} completed successfully.`
  }
  const parts: string[] = []
  if (b.success > 0) parts.push(`${b.success} succeeded`)
  if (b.skipped > 0) parts.push(`${b.skipped} skipped`)
  if (b.partial > 0) parts.push(`${b.partial} partial`)
  return `${b.total} collector${b.total > 1 ? 's' : ''} executed: ${parts.join(', ')}. No error-level failures detected.`
})
</script>

<style scoped>
.ea-cluster {
  margin-bottom: 10px;
  padding: 0;
  overflow: hidden;
  border-radius: var(--nv-radius-lg);
}
.ea-cluster--critical { border-left: 3px solid var(--nv-error); }
.ea-cluster--high { border-left: 3px solid var(--nv-warning); }
.ea-cluster--medium { border-left: 3px solid var(--nv-info); }
.ea-cluster--low { border-left: 3px solid var(--nv-text-tertiary); }

.ea-cluster__header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  cursor: pointer;
  transition: background var(--nv-duration-base) var(--nv-ease);
}
.ea-cluster__header:hover {
  background: var(--nv-glass-bg-light);
}
.ea-cluster__count {
  font-weight: 700;
  font-size: 0.8125rem;
  color: var(--nv-error);
  flex-shrink: 0;
  min-width: 32px;
}
.ea-cluster__msg {
  font-size: 0.8125rem;
  color: var(--nv-text-primary);
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ea-cluster__duts {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
}
.ea-cluster__chevron {
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
}

.ea-cluster__body {
  padding: 12px 14px;
  border-top: 1px solid var(--nv-glass-border);
}
.ea-cluster__entries {
  max-height: 240px;
  overflow-y: auto;
}

.ea-entry {
  display: flex;
  gap: 8px;
  padding: 5px 0;
  border-bottom: 1px solid var(--nv-glass-border);
  font-size: 0.75rem;
  cursor: pointer;
  transition: background var(--nv-duration-base) var(--nv-ease);
}
.ea-entry:hover { background: var(--nv-glass-bg-light); }
.ea-entry:last-child { border-bottom: none; }
.ea-entry__dut { color: var(--nv-accent); font-weight: 600; flex-shrink: 0; min-width: 80px; }
.ea-entry__cid { font-family: var(--nv-font-mono); color: var(--nv-text-secondary); flex-shrink: 0; min-width: 80px; }
.ea-entry__msg { color: var(--nv-text-primary); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.ea-sev-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.ea-sev-dot--critical { background: var(--nv-error); }
.ea-sev-dot--high { background: var(--nv-warning); }
.ea-sev-dot--medium { background: var(--nv-info); }
.ea-sev-dot--low { background: var(--nv-text-tertiary); }

.ea-sev-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
  font-size: 0.6875rem;
}
.ea-sev-badge--critical { background: var(--nv-error-muted); color: var(--nv-error); }
.ea-sev-badge--high { background: var(--nv-warning-muted); color: var(--nv-warning); }
.ea-sev-badge--medium { background: var(--nv-info-muted); color: var(--nv-info); }
.ea-sev-badge--low { background: rgba(100, 116, 139, 0.1); color: var(--nv-text-tertiary); }

.ea-known-tag {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: 6px;
  font-size: 0.625rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  background: var(--nv-info-muted);
  color: var(--nv-info);
  flex-shrink: 0;
}

.ea-known-issue {
  border-radius: var(--nv-radius-md);
  padding: 12px 14px;
  margin-bottom: 12px;
  border: 1px solid var(--nv-glass-border);
}
.ea-known-issue__title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--nv-text-primary);
  margin-bottom: 6px;
}
.ea-known-issue__desc {
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  margin-bottom: 8px;
  line-height: 1.5;
}
.ea-known-issue__fix {
  font-size: 0.75rem;
  color: var(--nv-success);
  line-height: 1.5;
  padding: 8px 12px;
  background: var(--nv-success-muted);
  border-radius: var(--nv-radius-sm);
}

.ea-empty-state {
  padding: 40px 32px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  text-align: center;
}
.ea-empty-state__icon { margin-bottom: 4px; }
.ea-empty-state__title {
  font-size: 1rem;
  font-weight: 700;
  color: var(--nv-text-primary);
  margin: 0;
}
.ea-empty-state__desc {
  font-size: 0.8125rem;
  color: var(--nv-text-secondary);
  max-width: 480px;
  margin: 0;
  line-height: 1.5;
}
.ea-empty-state__breakdown {
  display: flex;
  gap: 20px;
  margin-top: 12px;
}
.ea-empty-state__stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 8px 14px;
  background: var(--nv-glass-bg-light);
  border-radius: var(--nv-radius-md);
  border: 1px solid var(--nv-glass-border);
}
.ea-empty-state__stat-value {
  font-size: 1.125rem;
  font-weight: 700;
  font-family: var(--nv-font-mono);
}
.ea-empty-state__stat-label {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--nv-text-tertiary);
  font-weight: 600;
}
</style>
