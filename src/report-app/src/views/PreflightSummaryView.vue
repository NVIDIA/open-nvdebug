<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Aggregating preflight results..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Preflight Summary' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">Preflight Summary</h2>

        <!-- Overall health -->
        <div class="ps-health nv-glass" style="padding: 20px; border-radius: var(--nv-radius-lg); margin-bottom: 16px; text-align: center;">
          <template v-if="allSkipped">
            <div class="ps-health__score" style="color: var(--nv-text-tertiary);">&mdash;</div>
            <div style="font-size: 0.6875rem; color: var(--nv-text-tertiary); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600;">All Checks Skipped / N/A</div>
            <div style="font-size: 0.75rem; color: var(--nv-text-secondary); margin-top: 4px;">
              {{ totalSkipped }} skipped &middot; {{ totalDuts }} DUTs checked &mdash; no pass/fail data available
            </div>
          </template>
          <template v-else>
            <div class="ps-health__score" :style="{ color: healthScore >= 90 ? 'var(--nv-success)' : healthScore >= 60 ? 'var(--nv-warning)' : 'var(--nv-error)' }">
              {{ healthScore.toFixed(0) }}%
            </div>
            <div style="font-size: 0.6875rem; color: var(--nv-text-tertiary); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600;">Preflight Pass Rate</div>
            <div style="font-size: 0.75rem; color: var(--nv-text-secondary); margin-top: 4px;">
              {{ totalPassed }} passed &middot; {{ totalFailed }} failed &middot; {{ totalWarning }} warnings<template v-if="totalSkipped > 0"> &middot; {{ totalSkipped }} skipped</template> &middot; {{ totalDuts }} DUTs checked
            </div>
          </template>
        </div>

        <!-- Empty state -->
        <div v-if="checkSummaries.length === 0" class="nv-glass" style="padding: 32px; text-align: center; border-radius: var(--nv-radius-lg);">
          <p style="font-size: 0.875rem; color: var(--nv-text-secondary); margin: 0;">No preflight data available.</p>
        </div>

        <!-- Per-check summary -->
        <template v-else>
          <h3 class="nv-section-title" style="margin-bottom: 12px;">Per-Check Results</h3>
          <div class="ps-checks">
            <div v-for="check in checkSummaries" :key="check.name" class="ps-check nv-glass" @click="toggleCheck(check.name)">
              <div class="ps-check__header">
                <span :class="['ps-check__dot', check.failCount > 0 ? 'ps-check__dot--fail' : 'ps-check__dot--pass']"></span>
                <span class="ps-check__name">{{ check.name }}</span>
                <span class="ps-check__group">{{ check.group }}</span>
                <span v-if="check.skipCount + check.naCount > 0" class="ps-check__skip">{{ check.skipCount + check.naCount }} skipped</span>
                <span class="ps-check__rate" :style="{ color: check.applicable === 0 ? 'var(--nv-text-tertiary)' : check.passRate >= 100 ? 'var(--nv-success)' : check.passRate >= 50 ? 'var(--nv-warning)' : 'var(--nv-error)' }">
                  {{ check.applicable === 0 ? 'N/A' : `${check.passCount}/${check.applicable}` }}
                </span>
              </div>
              <div class="ps-check__bar">
                <div class="ps-check__bar-fill ps-check__bar-fill--pass" :style="{ width: check.applicable > 0 ? (check.passCount / check.applicable * 100) + '%' : '0%' }"></div>
                <div class="ps-check__bar-fill ps-check__bar-fill--warn" :style="{ width: check.applicable > 0 ? (check.warnCount / check.applicable * 100) + '%' : '0%' }"></div>
                <div class="ps-check__bar-fill ps-check__bar-fill--fail" :style="{ width: check.applicable > 0 ? (check.failCount / check.applicable * 100) + '%' : '0%' }"></div>
              </div>

              <!-- Expanded: failed DUTs -->
              <div v-if="expandedChecks.has(check.name) && check.failedDuts.length > 0" class="ps-check__detail">
                <strong style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">Failed on:</strong>
                <div v-for="fd in check.failedDuts" :key="fd.dutId" class="ps-check__dut" @click.stop="router.push(`/dut/${encodeURIComponent(fd.dutId)}/preflight`)">
                  <span style="color: var(--nv-accent); font-weight: 600;">{{ fd.dutId }}</span>
                  <span style="color: var(--nv-text-tertiary);">{{ fd.details }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Per-DUT overview -->
          <h3 class="nv-section-title" style="margin: 20px 0 12px;">Per-DUT Preflight Status</h3>
          <div class="nv-card">
            <DataTable
              :columns="dutColumns"
              :data="dutPreflightData"
              :searchable="true"
              @row-click="(row: Record<string, any>) => router.push(`/dut/${encodeURIComponent(row.dutId)}/preflight`)"
            >
              <template #cell-passRate="{ value }">
                <span :style="{ color: Number(value) >= 100 ? 'var(--nv-success)' : Number(value) >= 50 ? 'var(--nv-warning)' : 'var(--nv-error)', fontWeight: 600 }">{{ Number(value).toFixed(0) }}%</span>
              </template>
            </DataTable>
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
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import DataTable from '@/components/common/DataTable.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const router = useRouter()
const manifestStore = useManifestStore()
const expandedChecks = ref(new Set<string>())

function toggleCheck(name: string) {
  const next = new Set(expandedChecks.value)
  if (next.has(name)) next.delete(name)
  else next.add(name)
  expandedChecks.value = next
}

const preflightData = computed(() => manifestStore.preflight?.per_dut ?? [])
const totalDuts = computed(() => preflightData.value.length)

interface CheckSummary {
  name: string
  group: string
  total: number
  passCount: number
  failCount: number
  warnCount: number
  skipCount: number
  naCount: number
  applicable: number
  passRate: number
  failedDuts: { dutId: string; details: string }[]
}

const checkSummaries = computed<CheckSummary[]>(() => {
  const map = new Map<string, CheckSummary>()
  for (const dutPf of preflightData.value) {
    if (!dutPf.checks) continue
    for (const check of dutPf.checks) {
      if (!map.has(check.name)) {
        map.set(check.name, { name: check.name, group: check.group, total: 0, passCount: 0, failCount: 0, warnCount: 0, skipCount: 0, naCount: 0, applicable: 0, passRate: 0, failedDuts: [] })
      }
      const s = map.get(check.name)!
      s.total++
      if (check.status === 'pass') { s.passCount++; s.applicable++ }
      else if (check.status === 'fail') {
        s.failCount++
        s.applicable++
        s.failedDuts.push({ dutId: dutPf.dut_id, details: check.details })
      }
      else if (check.status === 'warning') { s.warnCount++; s.applicable++ }
      else if (check.status === 'skip') s.skipCount++
      else s.naCount++
    }
  }
  for (const s of map.values()) {
    s.passRate = s.applicable > 0 ? (s.passCount / s.applicable) * 100 : 0
  }
  return [...map.values()].sort((a, b) => a.passRate - b.passRate || a.name.localeCompare(b.name))
})

const totalPassed = computed(() => checkSummaries.value.reduce((s, c) => s + c.passCount, 0))
const totalFailed = computed(() => checkSummaries.value.reduce((s, c) => s + c.failCount, 0))
const totalWarning = computed(() => checkSummaries.value.reduce((s, c) => s + c.warnCount, 0))
const totalSkipped = computed(() => checkSummaries.value.reduce((s, c) => s + c.skipCount + c.naCount, 0))
const totalApplicable = computed(() => totalPassed.value + totalFailed.value + totalWarning.value)
const healthScore = computed(() => totalApplicable.value > 0 ? (totalPassed.value / totalApplicable.value) * 100 : 0)
const allSkipped = computed(() => totalApplicable.value === 0 && totalSkipped.value > 0)

const dutColumns = [
  { key: 'dutId', label: 'DUT', sortable: true },
  { key: 'pass', label: 'Pass', sortable: true },
  { key: 'fail', label: 'Fail', sortable: true },
  { key: 'warn', label: 'Warning', sortable: true },
  { key: 'total', label: 'Total', sortable: true },
  { key: 'passRate', label: 'Pass Rate', sortable: true },
]

const dutPreflightData = computed(() =>
  preflightData.value.map(dpf => {
    let pass = 0, fail = 0, warn = 0, skip = 0
    for (const c of (dpf.checks ?? [])) {
      if (c.status === 'pass') pass++
      else if (c.status === 'fail') fail++
      else if (c.status === 'warning') warn++
      else skip++
    }
    const applicable = pass + fail + warn
    return {
      dutId: dpf.dut_id,
      pass,
      fail,
      warn,
      skip,
      total: applicable,
      passRate: applicable > 0 ? ((pass / applicable) * 100).toFixed(1) : '0.0',
    }
  })
)
</script>

<style scoped>
.ps-health__score {
  font-size: 2.5rem;
  font-weight: 800;
  font-family: var(--nv-font-mono);
}
.ps-checks {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.ps-check {
  padding: 10px 14px;
  border-radius: var(--nv-radius-lg);
  cursor: pointer;
  transition: box-shadow var(--nv-duration-base) var(--nv-ease);
}
.ps-check:hover { box-shadow: var(--nv-glass-shadow); }
.ps-check__header {
  display: flex;
  align-items: center;
  gap: 8px;
}
.ps-check__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.ps-check__dot--pass { background: var(--nv-success); }
.ps-check__dot--fail { background: var(--nv-error); }
.ps-check__name {
  font-size: 0.8125rem;
  font-weight: 600;
  color: var(--nv-text-primary);
  flex: 1;
}
.ps-check__group {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
}
.ps-check__skip {
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  background: var(--nv-glass-bg-light);
  padding: 1px 6px;
  border-radius: 8px;
  flex-shrink: 0;
}
.ps-check__rate {
  font-size: 0.8125rem;
  font-weight: 700;
  font-family: var(--nv-font-mono);
  flex-shrink: 0;
}
.ps-check__bar {
  height: 4px;
  border-radius: 2px;
  background: var(--nv-glass-bg-light);
  display: flex;
  overflow: hidden;
  margin-top: 6px;
}
.ps-check__bar-fill { height: 100%; }
.ps-check__bar-fill--pass { background: var(--nv-success); }
.ps-check__bar-fill--warn { background: var(--nv-warning); }
.ps-check__bar-fill--fail { background: var(--nv-error); }
.ps-check__detail {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--nv-glass-border);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.ps-check__dut {
  display: flex;
  gap: 8px;
  font-size: 0.6875rem;
  padding: 3px 0;
  cursor: pointer;
}
.ps-check__dut:hover { text-decoration: underline; }
</style>
