<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Analyzing collection efficiency..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Collection Efficiency' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">Collection Efficiency</h2>

        <!-- Funnel -->
        <div class="ce-funnel nv-glass" style="padding: 20px; border-radius: var(--nv-radius-lg); margin-bottom: 20px;">
          <h3 class="nv-section-title" style="margin: 0 0 16px;">Collection Funnel</h3>
          <div class="ce-funnel__steps">
            <div v-for="(step, i) in funnelSteps" :key="step.label" class="ce-funnel__step">
              <div class="ce-funnel__bar" :style="{ width: step.pct + '%', background: step.color }">
                <span class="ce-funnel__count">{{ step.count }}</span>
              </div>
              <div class="ce-funnel__label">
                {{ step.label }}
                <span v-if="i > 0" class="ce-funnel__delta">(-{{ funnelSteps[i - 1].count - step.count }})</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Stats -->
        <div class="ce-stats">
          <div class="ce-stat nv-glass">
            <span class="ce-stat__value" style="color: var(--nv-accent);">{{ summary?.overall_collection_pct?.toFixed(1) ?? 0 }}%</span>
            <span class="ce-stat__label">Overall Efficiency</span>
          </div>
          <div class="ce-stat nv-glass">
            <span class="ce-stat__value">{{ summary?.total_collectors_executed ?? 0 }}</span>
            <span class="ce-stat__label">Executed</span>
          </div>
          <div class="ce-stat nv-glass">
            <span class="ce-stat__value">{{ summary?.total_collectors_in_catalog ?? 0 }}</span>
            <span class="ce-stat__label">In Catalog</span>
          </div>
          <div class="ce-stat nv-glass">
            <span class="ce-stat__value" style="color: var(--nv-text-tertiary);">{{ summary?.total_collectors_filtered_out ?? 0 }}</span>
            <span class="ce-stat__label">Filtered Out</span>
          </div>
          <div class="ce-stat nv-glass">
            <span class="ce-stat__value" style="color: var(--nv-success);">{{ summary?.status_counts?.success ?? 0 }}</span>
            <span class="ce-stat__label">Successful</span>
          </div>
          <div class="ce-stat nv-glass">
            <span class="ce-stat__value" style="color: var(--nv-error);">{{ summary?.status_counts?.error ?? 0 }}</span>
            <span class="ce-stat__label">Failed</span>
          </div>
        </div>

        <!-- Not-executed catalog collectors -->
        <div v-if="notExecuted.length > 0" style="margin-top: 20px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">
            Catalog Collectors Not Executed
            <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary); margin-left: 6px;">{{ notExecuted.length }}</span>
          </h3>
          <div class="nv-card">
            <DataTable
              :columns="notExecColumns"
              :data="notExecuted"
              :searchable="true"
            />
          </div>
        </div>

        <!-- Per-level breakdown -->
        <div v-if="levelBreakdown.length > 0" style="margin-top: 20px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">By Collection Level</h3>
          <div class="ce-level-grid">
            <div v-for="lvl in levelBreakdown" :key="lvl.level" class="ce-level-card nv-glass">
              <div style="font-size: 0.875rem; font-weight: 700; color: var(--nv-text-primary);">{{ lvl.level || 'Unknown' }}</div>
              <div style="font-size: 0.6875rem; color: var(--nv-text-tertiary); margin-top: 4px;">{{ lvl.catalog }} in catalog &middot; {{ lvl.executed }} executed</div>
              <div class="sh-card__bar" style="margin-top: 6px;">
                <div class="sh-card__bar-fill sh-card__bar-fill--success" :style="{ width: lvl.catalog > 0 ? (lvl.executed / lvl.catalog * 100) + '%' : '0%' }"></div>
              </div>
            </div>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import DataTable from '@/components/common/DataTable.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const manifestStore = useManifestStore()
const summary = computed(() => manifestStore.collectionSummary)

const funnelSteps = computed(() => {
  const s = summary.value
  if (!s) return []
  const catalogTotal = s.total_collectors_in_catalog || 0
  const applicable = catalogTotal - (s.total_collectors_filtered_out || 0)
  const executed = s.total_collectors_executed || 0
  const successful = s.status_counts?.success ?? 0
  const max = Math.max(catalogTotal, 1)
  return [
    { label: 'In Catalog', count: catalogTotal, pct: 100, color: 'var(--nv-text-tertiary)' },
    { label: 'Applicable', count: applicable, pct: (applicable / max) * 100, color: 'var(--nv-info)' },
    { label: 'Executed', count: executed, pct: (executed / max) * 100, color: 'var(--nv-accent)' },
    { label: 'Successful', count: successful, pct: (successful / max) * 100, color: 'var(--nv-success)' },
  ]
})

const executedIds = computed(() => {
  const ids = new Set<string>()
  for (const dut of manifestStore.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.status !== 'not_ran') ids.add(c.id)
      }
    }
  }
  return ids
})

const notExecuted = computed(() => {
  const exec = executedIds.value
  return manifestStore.collectorCatalog
    .filter(c => !exec.has(c.id))
    .map(c => ({
      id: c.id,
      name: c.name,
      group: c.group,
      collection_level: c.collection_level || '—',
      description: c.description || '—',
      applicable_baseboards: c.applicable_baseboards?.join(', ') || 'All',
    }))
})

const notExecColumns = [
  { key: 'id', label: 'ID', sortable: true },
  { key: 'name', label: 'Name', sortable: true },
  { key: 'group', label: 'Group', sortable: true },
  { key: 'collection_level', label: 'Level', sortable: true },
  { key: 'description', label: 'Description', sortable: true },
]

const levelBreakdown = computed(() => {
  const catalogLevels = new Map<string, number>()
  for (const c of manifestStore.collectorCatalog) {
    const lv = c.collection_level || 'Unknown'
    catalogLevels.set(lv, (catalogLevels.get(lv) ?? 0) + 1)
  }
  const execLevels = new Map<string, number>()
  const exec = executedIds.value
  for (const c of manifestStore.collectorCatalog) {
    if (!exec.has(c.id)) continue
    const lv = c.collection_level || 'Unknown'
    execLevels.set(lv, (execLevels.get(lv) ?? 0) + 1)
  }
  return [...catalogLevels.entries()].map(([level, catalog]) => ({
    level,
    catalog,
    executed: execLevels.get(level) ?? 0,
  })).sort((a, b) => a.level.localeCompare(b.level))
})
</script>

<style scoped>
.ce-funnel { margin-bottom: 20px; }
.ce-funnel__steps { display: flex; flex-direction: column; gap: 8px; }
.ce-funnel__step { display: flex; align-items: center; gap: 12px; }
.ce-funnel__bar {
  height: 28px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  padding: 0 10px;
  min-width: 40px;
  transition: width 0.5s ease;
}
.ce-funnel__count {
  font-size: 0.8125rem;
  font-weight: 700;
  color: white;
  text-shadow: 0 1px 2px rgba(0,0,0,0.3);
}
.ce-funnel__label {
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  white-space: nowrap;
}
.ce-funnel__delta {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
}
.ce-stats {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}
.ce-stat {
  padding: 14px;
  border-radius: var(--nv-radius-lg);
  text-align: center;
}
.ce-stat__value {
  display: block;
  font-size: 1.5rem;
  font-weight: 700;
  font-family: var(--nv-font-mono);
  color: var(--nv-text-primary);
}
.ce-stat__label {
  display: block;
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--nv-text-tertiary);
  font-weight: 600;
  margin-top: 2px;
}
.ce-level-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 10px;
}
.ce-level-card {
  padding: 12px 14px;
  border-radius: var(--nv-radius-lg);
}
.sh-card__bar {
  height: 4px;
  border-radius: 2px;
  background: var(--nv-glass-bg-light);
  display: flex;
  overflow: hidden;
}
.sh-card__bar-fill { height: 100%; }
.sh-card__bar-fill--success { background: var(--nv-success); }
</style>
