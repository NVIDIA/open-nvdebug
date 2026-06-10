<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Analyzing failure correlations..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Co-Failure Analysis' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">Co-Failure Analysis</h2>
        <p style="font-size: 0.75rem; color: var(--nv-text-tertiary); margin: 0 0 16px;">
          Identifies collectors that frequently fail together across DUTs, suggesting shared root causes.
        </p>

        <!-- Empty state -->
        <div v-if="result.clusters.length === 0 && result.pairs.length === 0" class="nv-glass" style="padding: 40px; text-align: center; border-radius: var(--nv-radius-lg);">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--nv-success)" stroke-width="1.5" stroke-linecap="round" style="margin-bottom: 12px;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <h3 style="font-size: 1rem; font-weight: 700; color: var(--nv-text-primary); margin: 0 0 4px;">No Correlated Failures</h3>
          <p style="font-size: 0.8125rem; color: var(--nv-text-secondary); margin: 0;">No collector pairs consistently fail together across multiple DUTs.</p>
        </div>

        <template v-else>
          <!-- Failure Clusters -->
          <div v-if="result.clusters.length > 0" style="margin-bottom: 24px;">
            <h3 class="nv-section-title" style="margin-bottom: 12px;">
              Failure Clusters
              <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary); margin-left: 6px;">{{ result.clusters.length }}</span>
            </h3>
            <div v-for="cl in result.clusters" :key="cl.id" class="cf-cluster nv-glass">
              <div class="cf-cluster__header" @click="toggleCluster(cl.id)">
                <svg :style="{ transform: expandedClusters.has(cl.id) ? 'rotate(90deg)' : '' }" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" style="transition: transform 0.15s ease; flex-shrink: 0;"><polyline points="9 18 15 12 9 6"/></svg>
                <span class="cf-cluster__count">{{ cl.collectors.length }} collectors</span>
                <span class="cf-cluster__duts">{{ cl.dutIds.length }} DUTs affected</span>
                <span v-if="cl.sharedService" class="cf-cluster__tag cf-cluster__tag--service">{{ cl.sharedService }}</span>
                <span v-if="cl.sharedDependency" class="cf-cluster__tag cf-cluster__tag--dep">depends: {{ cl.sharedDependency }}</span>
              </div>
              <div v-if="expandedClusters.has(cl.id)" class="cf-cluster__body">
                <div v-if="cl.sharedService || cl.sharedDependency" class="cf-hint nv-glass--accent">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--nv-info)" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                  <span v-if="cl.sharedService">All collectors belong to the <strong>{{ cl.sharedService }}</strong> service — check {{ cl.sharedService }} connectivity/configuration.</span>
                  <span v-else-if="cl.sharedDependency">All collectors share dependency <strong>{{ cl.sharedDependency }}</strong> — this dependency may be the root cause.</span>
                </div>
                <div style="margin-bottom: 8px;">
                  <strong style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">Collectors:</strong>
                  <span v-for="c in cl.collectors" :key="c" class="cf-pill">{{ c }}</span>
                </div>
                <div>
                  <strong style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">Affected DUTs:</strong>
                  <span v-for="d in cl.dutIds" :key="d" class="cf-dut-link" @click="router.push(`/dut/${encodeURIComponent(d)}`)">{{ d }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Top pairs table -->
          <div v-if="result.pairs.length > 0">
            <h3 class="nv-section-title" style="margin-bottom: 12px;">
              Top Co-Failure Pairs
              <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary); margin-left: 6px;">{{ result.pairs.length }}</span>
            </h3>
            <div class="nv-card">
              <DataTable
                :columns="pairColumns"
                :data="pairRows"
                :searchable="true"
              >
                <template #cell-jaccard="{ value }">
                  <span :style="{ color: Number(value) >= 0.8 ? 'var(--nv-error)' : Number(value) >= 0.5 ? 'var(--nv-warning)' : 'var(--nv-text-secondary)', fontWeight: 600 }">{{ (Number(value) * 100).toFixed(0) }}%</span>
                </template>
              </DataTable>
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
import { analyzeCoFailures } from '@/composables/useCoFailureAnalysis'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import DataTable from '@/components/common/DataTable.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const router = useRouter()
const manifestStore = useManifestStore()
const expandedClusters = ref(new Set<number>())

const result = computed(() =>
  manifestStore.manifest ? analyzeCoFailures(manifestStore.manifest) : { pairs: [], clusters: [] }
)

function toggleCluster(id: number) {
  const next = new Set(expandedClusters.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expandedClusters.value = next
}

const pairColumns = [
  { key: 'a', label: 'Collector A', sortable: true },
  { key: 'b', label: 'Collector B', sortable: true },
  { key: 'coCount', label: 'Co-Failures', sortable: true },
  { key: 'jaccard', label: 'Correlation', sortable: true },
  { key: 'duts', label: 'DUTs', sortable: true },
]

const pairRows = computed(() =>
  result.value.pairs.map(p => ({
    a: p.a,
    b: p.b,
    coCount: p.coCount,
    jaccard: p.jaccard,
    duts: p.dutIds.join(', '),
  }))
)
</script>

<style scoped>
.cf-cluster {
  border-radius: var(--nv-radius-lg);
  margin-bottom: 10px;
  overflow: hidden;
}
.cf-cluster__header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  cursor: pointer;
  transition: background var(--nv-duration-base) var(--nv-ease);
}
.cf-cluster__header:hover { background: var(--nv-glass-bg-light); }
.cf-cluster__count {
  font-size: 0.8125rem;
  font-weight: 700;
  color: var(--nv-text-primary);
}
.cf-cluster__duts {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
}
.cf-cluster__tag {
  display: inline-flex;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 0.625rem;
  font-weight: 600;
}
.cf-cluster__tag--service { background: var(--nv-info-muted); color: var(--nv-info); }
.cf-cluster__tag--dep { background: var(--nv-warning-muted); color: var(--nv-warning); }
.cf-cluster__body {
  padding: 12px 14px;
  border-top: 1px solid var(--nv-glass-border);
}
.cf-hint {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  padding: 10px 12px;
  border-radius: var(--nv-radius-md);
  margin-bottom: 10px;
  border: 1px solid var(--nv-glass-border);
  line-height: 1.4;
}
.cf-pill {
  display: inline-flex;
  padding: 2px 8px;
  border-radius: 8px;
  font-size: 0.6875rem;
  font-family: var(--nv-font-mono);
  background: var(--nv-glass-bg-light);
  color: var(--nv-text-primary);
  margin: 2px 4px 2px 0;
}
.cf-dut-link {
  display: inline-flex;
  padding: 2px 6px;
  font-size: 0.6875rem;
  color: var(--nv-accent);
  cursor: pointer;
  font-weight: 600;
  margin: 2px 4px 2px 0;
}
.cf-dut-link:hover { text-decoration: underline; }
</style>
