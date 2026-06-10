<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Dependency Graph' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 20px;">Collector Dependencies</h2>

    <!-- DUT filter (pills) -->
    <div class="nv-glass--subtle nv-filter-bar" style="margin-bottom: 16px; padding: 10px 16px;">
      <DutPillSelector
        v-model="dutFilter"
        :options="dutPillOptions"
        :multiple="false"
      />
      <span v-if="!hasCatalog && !dutFilter" style="font-size: 0.75rem; color: var(--nv-text-tertiary);">
        No collector catalog found — select a DUT to view its dependency graph
      </span>
      <span v-if="nodes.length > 0" style="font-size: 0.75rem; color: var(--nv-text-tertiary); margin-left: auto;">
        {{ collectorCountLabel }}<template v-if="dependencyCount > 0">, {{ dependencyCount }} dependencies</template><template v-if="!dutFilter"> &mdash; select a DUT to see execution results</template>
      </span>
    </div>

    <!-- Graph -->
    <div class="nv-card" style="padding: 24px; overflow-x: auto; min-height: 400px;">
      <template v-if="layers.length > 0">
        <div v-for="(layer, depth) in layers" :key="depth" class="dep-layer">
          <div class="dep-layer__label">Layer {{ depth }}</div>
          <div
            v-for="node in layer"
            :key="node.id"
            @click="onNodeClick(node)"
            class="dep-node nv-glass--subtle"
            :class="{ 'dep-node--clickable': !!dutFilter, [`dep-node--${node.status}`]: !!node.status }"
          >
            <div class="dep-node__id">{{ node.id }}</div>
            <div class="dep-node__name">{{ node.name }}</div>
            <div v-if="node.status" style="margin-top: 4px;">
              <StatusBadge :status="node.status" />
            </div>
            <div v-if="node.deps.length > 0" class="dep-node__deps">
              deps: {{ node.deps.map(d => typeof d === 'object' ? (d as any).name || String(d) : d).join(', ') }}
            </div>
          </div>
        </div>
      </template>

      <div v-else-if="nodes.length > 0 && !hasDependencies" class="dep-empty-state nv-glass">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" style="color: var(--nv-text-tertiary);"><path d="M12 2L2 7l10 5 10-5-10-5z" stroke="currentColor" stroke-width="1.5"/><path d="M2 17l10 5 10-5" stroke="currentColor" stroke-width="1.5"/><path d="M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.5"/></svg>
        <div style="font-weight: 600; font-size: 0.875rem; color: var(--nv-text-primary); margin-top: 8px;">No Dependency Relationships</div>
        <div style="font-size: 0.75rem; color: var(--nv-text-secondary); max-width: 400px;">
          {{ nodes.length }} collectors found but none declare dependencies. All collectors ran independently.
        </div>
      </div>

      <div v-else class="dep-empty-state nv-glass">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" style="color: var(--nv-text-tertiary);"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><path d="M12 8v4M12 16h.01" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        <div style="font-weight: 600; font-size: 0.875rem; color: var(--nv-text-primary); margin-top: 8px;">No Data Available</div>
        <div style="font-size: 0.75rem; color: var(--nv-text-secondary); max-width: 400px;">
          {{ hasCatalog ? 'Select a DUT to view collector dependencies.' : 'No collector catalog data found. Select a DUT above to view its collectors.' }}
        </div>
      </div>
    </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import StatusBadge from '@/components/common/StatusBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import DutPillSelector from '@/components/common/DutPillSelector.vue'
import type { PillOption } from '@/components/common/DutPillSelector.vue'

const manifestStore = useManifestStore()
const router = useRouter()
const dutFilter = ref('')

const hasCatalog = computed(() => manifestStore.collectorCatalog.length > 0)

const dutPillOptions = computed<PillOption[]>(() => {
  const opts: PillOption[] = []
  if (hasCatalog.value) {
    opts.push({ id: '', label: 'Catalog (all)' })
  }
  for (const dut of manifestStore.duts) {
    opts.push({ id: dut.id, label: dut.id, status: dut.overall_status })
  }
  return opts
})

onMounted(() => {
  if (!hasCatalog.value && manifestStore.duts.length > 0) {
    dutFilter.value = manifestStore.duts[0].id
  }
})

interface GraphNode {
  id: string
  name: string
  group: string
  deps: string[]
  status: string | null
}

const nodes = computed<GraphNode[]>(() => {
  if (dutFilter.value) {
    const dut = manifestStore.dutById(dutFilter.value)
    if (!dut) return []
    return dut.collector_groups.flatMap(g =>
      g.collectors.map(c => ({
        id: c.id, name: c.name, group: g.name,
        deps: c.dependencies ?? [],
        status: c.status,
      }))
    )
  }
  if (hasCatalog.value) {
    return manifestStore.collectorCatalog.map(c => ({
      id: c.id, name: c.name, group: c.group,
      deps: c.dependencies ?? [],
      status: null,
    }))
  }
  return []
})

const hasDependencies = computed(() => nodes.value.some(n => n.deps.length > 0))

const dependencyCount = computed(() =>
  nodes.value.reduce((sum, n) => sum + n.deps.length, 0)
)

const collectorCountLabel = computed(() => {
  const total = nodes.value.length
  if (!dutFilter.value) return `${total} collectors in catalog`
  const ran = nodes.value.filter(n => n.status && n.status !== 'not_ran').length
  const notRan = total - ran
  return `${ran} executed / ${total} total` + (notRan > 0 ? ` (${notRan} not ran)` : '')
})

const layers = computed<GraphNode[][]>(() => {
  if (!hasDependencies.value) return []

  const nodeMap = new Map(nodes.value.map(n => [n.id, n]))
  const depths = new Map<string, number>()

  function getDepth(id: string, visited = new Set<string>()): number {
    if (depths.has(id)) return depths.get(id)!
    if (visited.has(id)) return 0
    visited.add(id)
    const node = nodeMap.get(id)
    if (!node || node.deps.length === 0) {
      depths.set(id, 0)
      return 0
    }
    const maxDep = Math.max(...node.deps.map(d => {
      const depId = typeof d === 'object' ? (d as any).name || String(d) : d
      return nodeMap.has(depId) ? getDepth(depId, visited) + 1 : 0
    }))
    depths.set(id, maxDep)
    return maxDep
  }

  for (const n of nodes.value) getDepth(n.id)

  const maxDepth = Math.max(0, ...depths.values())
  const result: GraphNode[][] = Array.from({ length: maxDepth + 1 }, () => [])
  for (const n of nodes.value) {
    result[depths.get(n.id) ?? 0].push(n)
  }
  return result.filter(layer => layer.length > 0)
})

function onNodeClick(node: GraphNode) {
  if (dutFilter.value) {
    const dut = manifestStore.dutById(dutFilter.value)
    const group = dut?.collector_groups.find(g => g.collectors.some(c => c.id === node.id))
    if (group) router.push(`/dut/${dutFilter.value}/${group.name}/${node.id}`)
  }
}
</script>

<style scoped>
.dep-layer {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
  align-items: flex-start;
}
.dep-layer__label {
  width: 60px;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  display: flex;
  align-items: center;
  font-weight: 600;
  flex-shrink: 0;
}

.dep-node {
  padding: 8px 12px;
  border: 2px solid var(--nv-glass-border);
  min-width: 100px;
  text-align: center;
  border-radius: 8px;
  transition: border-color 0.2s, background 0.2s, box-shadow 0.2s;
}
.dep-node--clickable {
  cursor: pointer;
}
.dep-node--clickable:hover {
  box-shadow: 0 0 0 2px var(--nv-accent);
}
.dep-node--success {
  border-color: var(--nv-success);
  background: var(--nv-success-muted);
}
.dep-node--error {
  border-color: var(--nv-error);
  background: var(--nv-error-muted);
}
.dep-node--partial {
  border-color: var(--nv-warning);
  background: var(--nv-warning-muted);
}
.dep-node--skipped {
  border-color: var(--nv-skipped);
}
.dep-node--not_ran {
  border-color: var(--nv-text-tertiary);
  opacity: 0.6;
}

.dep-node__id {
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--nv-text-primary);
}
.dep-node__name {
  font-size: 0.625rem;
  color: var(--nv-text-secondary);
}
.dep-node__deps {
  font-size: 0.5625rem;
  color: var(--nv-text-tertiary);
  margin-top: 2px;
}

.dep-empty-state {
  padding: 60px 40px;
  text-align: center;
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}
</style>
