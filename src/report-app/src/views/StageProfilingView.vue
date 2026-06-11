<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 0; font-size: 0.6875rem;">Filter by DUT</h4>
      <div style="padding: 4px 0; max-height: 240px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !dutFilter }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = ''"
        >All DUTs (aggregate)</a>
        <a
          v-for="d in manifestStore.duts"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': dutFilter === d.id }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = d.id"
        >{{ d.id }}</a>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Stage Summary</h4>
      <div style="padding: 8px 12px; display: flex; flex-direction: column; gap: 4px;">
        <div v-for="s in stageTotals" :key="s.stage" style="display: flex; justify-content: space-between; align-items: center; font-size: 0.6875rem;">
          <span :style="{ color: STAGE_COLORS[s.stage] || 'var(--nv-text-secondary)' }">{{ s.stage }}</span>
          <span style="font-family: var(--nv-font-mono); color: var(--nv-text-tertiary);">{{ s.total.toFixed(1) }}s</span>
        </div>
      </div>
    </div>

    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Profiling collector stages..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Stage Profiling' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">Collector Stage Profiling</h2>

        <!-- Legend -->
        <div style="display: flex; gap: 12px; margin-bottom: 16px; font-size: 0.6875rem; flex-wrap: wrap;">
          <span v-for="(color, stage) in STAGE_COLORS" :key="stage" style="display: flex; align-items: center; gap: 4px;">
            <span :style="{ display: 'inline-block', width: '10px', height: '10px', borderRadius: '2px', background: color }"></span>
            {{ stage }}
          </span>
        </div>

        <!-- Outliers -->
        <div v-if="outliers.length > 0" class="nv-glass" style="padding: 12px 16px; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <h3 class="nv-section-title" style="margin: 0 0 8px; font-size: 0.8125rem;">
            Stage Outliers
            <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary); margin-left: 6px;">{{ outliers.length }}</span>
          </h3>
          <div style="display: flex; flex-direction: column; gap: 4px; max-height: 160px; overflow-y: auto;">
            <div v-for="o in outliers" :key="o.id + o.dutId" style="font-size: 0.6875rem; color: var(--nv-text-secondary);">
              <span style="font-weight: 600; color: var(--nv-warning);">&#9888;</span>
              <span style="font-family: var(--nv-font-mono); font-weight: 600; color: var(--nv-text-primary);">{{ o.id }}</span>
              <span v-if="o.dutId" style="color: var(--nv-text-tertiary);">on {{ o.dutId }}</span>
              — <strong>{{ o.dominantStage }}</strong> stage is {{ o.dominantPct.toFixed(0) }}% of total time ({{ o.dominantTime.toFixed(1) }}s / {{ o.totalTime.toFixed(1) }}s)
            </div>
          </div>
        </div>

        <div v-if="collectorProfiles.length === 0" class="nv-glass--accent" style="padding: 32px; border-radius: var(--nv-radius-lg); text-align: center; color: var(--nv-text-secondary);">
          <p style="font-size: 0.875rem; margin: 0 0 8px; font-weight: 600; color: var(--nv-text-primary);">No stage timing data available</p>
          <p style="font-size: 0.75rem; margin: 0;">
            Stage profiling requires collectors to report per-stage timing (validation, discovery, execution, post_processing).
            This data is populated when the collection tool provides <code style="font-family: var(--nv-font-mono); background: var(--nv-glass-bg-light); padding: 1px 4px; border-radius: 3px;">stage_timing</code> in its output manifest.
          </p>
        </div>

        <!-- Stacked bars -->
        <div v-else class="sp-bars">
          <div v-for="c in collectorProfiles" :key="c.id + (c.dutId ?? '')" class="sp-row">
            <div class="sp-row__label" :title="c.name">
              <span class="sp-row__id">{{ c.id }}</span>
              <span v-if="c.dutId" class="sp-row__dut">{{ c.dutId }}</span>
            </div>
            <div class="sp-row__bar">
              <div
                v-for="s in STAGES"
                :key="s"
                class="sp-row__segment"
                :style="{ width: pct(c.stages[s] ?? 0, c.totalTime), background: STAGE_COLORS[s] }"
                :title="`${s}: ${(c.stages[s] ?? 0).toFixed(2)}s`"
              ></div>
            </div>
            <span class="sp-row__total">{{ c.totalTime.toFixed(1) }}s</span>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const manifestStore = useManifestStore()
const dutFilter = ref('')

const STAGES = ['validation', 'discovery', 'execution', 'post_processing'] as const
const STAGE_COLORS: Record<string, string> = {
  validation: 'var(--nv-info)',
  discovery: 'var(--nv-accent)',
  execution: 'var(--nv-success)',
  post_processing: 'var(--nv-warning)',
}

interface CollectorProfile {
  id: string
  name: string
  dutId: string
  stages: Record<string, number>
  totalTime: number
}

const timingLookup = computed(() => {
  const map = new Map<string, Record<string, number | null>>()
  for (const pd of manifestStore.manifest?.timing?.per_dut ?? []) {
    for (const c of pd.collectors) {
      if (c.stage_timing) map.set(`${pd.dut_id}::${c.id}`, c.stage_timing)
    }
  }
  return map
})

const collectorProfiles = computed<CollectorProfile[]>(() => {
  const profiles: CollectorProfile[] = []
  const duts = dutFilter.value ? manifestStore.duts.filter(d => d.id === dutFilter.value) : manifestStore.duts
  for (const dut of duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.status === 'not_ran' || c.execution_time <= 0) continue
        const st = c.stage_timing ?? timingLookup.value.get(`${dut.id}::${c.id}`) as Record<string, number | null> | undefined
        if (!st) continue
        const hasData = STAGES.some(s => (st[s] ?? 0) > 0)
        if (!hasData) continue
        const stages: Record<string, number> = {}
        let total = 0
        for (const s of STAGES) {
          const v = Number(st[s] ?? 0)
          stages[s] = v
          total += v
        }
        profiles.push({ id: c.id, name: c.name, dutId: dut.id, stages, totalTime: total || c.execution_time })
      }
    }
  }
  profiles.sort((a, b) => b.totalTime - a.totalTime)
  return profiles.slice(0, 100)
})

const stageTotals = computed(() =>
  STAGES.map(stage => ({
    stage,
    total: collectorProfiles.value.reduce((sum, c) => sum + (c.stages[stage] ?? 0), 0),
  }))
)

const outliers = computed(() =>
  collectorProfiles.value.filter(c => {
    if (c.totalTime <= 0) return false
    for (const s of STAGES) {
      const v = c.stages[s] ?? 0
      if (v / c.totalTime > 0.8 && c.totalTime > 2) return true
    }
    return false
  }).map(c => {
    let dominant = STAGES[0] as string
    let max = 0
    for (const s of STAGES) {
      if ((c.stages[s] ?? 0) > max) { max = c.stages[s] ?? 0; dominant = s }
    }
    return {
      id: c.id,
      dutId: c.dutId,
      dominantStage: dominant,
      dominantPct: (max / c.totalTime) * 100,
      dominantTime: max,
      totalTime: c.totalTime,
    }
  })
)

function pct(val: number, total: number) {
  return total > 0 ? `${(val / total) * 100}%` : '0%'
}
</script>

<style scoped>
.sp-bars {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.sp-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.sp-row__label {
  min-width: 140px;
  max-width: 140px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.sp-row__id {
  font-size: 0.6875rem;
  font-family: var(--nv-font-mono);
  font-weight: 600;
  color: var(--nv-text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.sp-row__dut {
  font-size: 0.5625rem;
  color: var(--nv-text-tertiary);
}
.sp-row__bar {
  flex: 1;
  height: 14px;
  border-radius: 3px;
  background: var(--nv-glass-bg-light);
  display: flex;
  overflow: hidden;
}
.sp-row__segment {
  height: 100%;
  transition: width 0.4s ease;
}
.sp-row__total {
  min-width: 50px;
  text-align: right;
  font-size: 0.625rem;
  font-family: var(--nv-font-mono);
  color: var(--nv-text-tertiary);
}
</style>
