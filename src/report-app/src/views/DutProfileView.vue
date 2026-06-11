<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-page" style="max-width: 960px; margin: 0 auto;">
      <PageLoader v-if="!manifestStore.loaded" message="Loading DUT profile..." />
      <template v-else-if="!dut">
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'DUT Profile' }]" />
        <div class="nv-glass" style="padding: 40px; text-align: center; border-radius: var(--nv-radius-lg);">
          <p style="color: var(--nv-text-secondary); font-size: 0.875rem;">DUT not found.</p>
        </div>
      </template>
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: dut.id, to: `/dut/${encodeURIComponent(dut.id)}` }, { label: 'Profile' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">{{ dut.id }} — Profile</h2>

        <!-- Identity -->
        <div class="dp-section nv-glass">
          <h3 class="dp-section__title">Identity</h3>
          <div class="dp-grid">
            <div class="dp-field"><span class="dp-field__label">DUT ID</span><span class="dp-field__value">{{ dut.id }}</span></div>
            <div class="dp-field"><span class="dp-field__label">Baseboard</span><span class="dp-field__value">{{ dut.baseboard || '—' }}</span></div>
            <div class="dp-field"><span class="dp-field__label">Node Type</span><span class="dp-field__value">{{ dut.node_type || '—' }}</span></div>
            <div class="dp-field"><span class="dp-field__label">BMC IP</span><span class="dp-field__value" style="font-family: var(--nv-font-mono);">{{ dut.bmc_ip || '—' }}</span></div>
            <div class="dp-field"><span class="dp-field__label">Model</span><span class="dp-field__value">{{ dut.system_info?.model || '—' }}</span></div>
            <div class="dp-field"><span class="dp-field__label">Part Number</span><span class="dp-field__value" style="font-family: var(--nv-font-mono);">{{ dut.system_info?.part_number || '—' }}</span></div>
            <div class="dp-field"><span class="dp-field__label">Serial Number</span><span class="dp-field__value" style="font-family: var(--nv-font-mono);">{{ dut.system_info?.serial_number || '—' }}</span></div>
            <div class="dp-field"><span class="dp-field__label">Overall Status</span><StatusBadge :status="dut.overall_status" /></div>
          </div>
        </div>

        <!-- Performance -->
        <div class="dp-section nv-glass">
          <h3 class="dp-section__title">Performance</h3>
          <div class="dp-perf-cards">
            <div class="dp-perf">
              <span class="dp-perf__value">{{ formatDuration(dut.execution_time) }}</span>
              <span class="dp-perf__label">Execution Time</span>
              <span v-if="perfRank.timeRank" class="dp-perf__rank">#{{ perfRank.timeRank }} / {{ manifestStore.duts.length }}</span>
            </div>
            <div class="dp-perf">
              <span class="dp-perf__value">{{ formatBytes(dut.log_size) }}</span>
              <span class="dp-perf__label">Log Size</span>
              <span v-if="perfRank.sizeRank" class="dp-perf__rank">#{{ perfRank.sizeRank }} / {{ manifestStore.duts.length }}</span>
            </div>
            <div class="dp-perf">
              <span class="dp-perf__value" :style="{ color: successRate >= 90 ? 'var(--nv-success)' : successRate >= 50 ? 'var(--nv-warning)' : 'var(--nv-error)' }">{{ successRate.toFixed(1) }}%</span>
              <span class="dp-perf__label">Success Rate</span>
            </div>
            <div class="dp-perf">
              <span class="dp-perf__value">{{ totalCollectors }}</span>
              <span class="dp-perf__label">Collectors Executed</span>
            </div>
          </div>
        </div>

        <!-- Status Breakdown -->
        <div class="dp-section nv-glass">
          <h3 class="dp-section__title">Collector Status</h3>
          <div style="display: flex; gap: 12px; flex-wrap: wrap;">
            <span v-for="(val, key) in dut.status_summary" :key="key" class="dp-status-pill" :class="`dp-status-pill--${key}`">
              {{ key.replace('_', ' ') }}: {{ val }}
            </span>
          </div>
        </div>

        <!-- Firmware -->
        <div v-if="dut.system_info?.firmware?.length" class="dp-section nv-glass">
          <h3 class="dp-section__title">Firmware</h3>
          <div class="dp-fw-list">
            <div v-for="fw in dut.system_info.firmware" :key="fw.id" class="dp-fw-item">
              <span class="dp-fw-item__name">{{ fw.name }}</span>
              <span class="dp-fw-item__ver">{{ fw.version }}</span>
              <span v-if="fw.component" class="dp-fw-item__comp">{{ fw.component }}</span>
              <span v-if="fw.date" class="dp-fw-item__date">{{ fw.date }}</span>
            </div>
          </div>
        </div>

        <!-- Anomalies for this DUT -->
        <div v-if="dutAnomalies.length > 0" class="dp-section nv-glass">
          <h3 class="dp-section__title">Anomalies <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary);">{{ dutAnomalies.length }}</span></h3>
          <div style="display: flex; flex-direction: column; gap: 6px;">
            <div v-for="a in dutAnomalies" :key="a.id" class="dp-anomaly-row">
              <span :class="['ano-sev-dot', `ano-sev-dot--${a.severity}`]"></span>
              <span style="font-size: 0.75rem; font-weight: 600; color: var(--nv-text-primary); flex: 1;">{{ a.title }}</span>
              <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">{{ a.severity }}</span>
            </div>
          </div>
        </div>

        <!-- Errors for this DUT -->
        <div v-if="dutErrors.length > 0" class="dp-section nv-glass">
          <h3 class="dp-section__title">Errors <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-error);">{{ dutErrors.length }}</span></h3>
          <div style="display: flex; flex-direction: column; gap: 4px; max-height: 200px; overflow-y: auto;">
            <div v-for="(e, i) in dutErrors.slice(0, 20)" :key="i" style="font-size: 0.75rem; color: var(--nv-text-secondary); padding: 4px 0; border-bottom: 1px solid var(--nv-glass-border);">
              <span style="font-weight: 600; color: var(--nv-accent); margin-right: 6px;">{{ e.collector_id }}</span>
              {{ e.message }}
            </div>
          </div>
        </div>

        <!-- Quick Links -->
        <div class="dp-section nv-glass">
          <h3 class="dp-section__title">Quick Links</h3>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            <router-link :to="`/dut/${encodeURIComponent(dut.id)}`" class="nv-btn nv-btn--ghost" style="font-size: 0.75rem;">DUT Overview</router-link>
            <router-link :to="`/dut/${encodeURIComponent(dut.id)}/preflight`" class="nv-btn nv-btn--ghost" style="font-size: 0.75rem;">Preflight</router-link>
            <router-link :to="`/dut/${encodeURIComponent(dut.id)}/firmware`" class="nv-btn nv-btn--ghost" style="font-size: 0.75rem;">Firmware</router-link>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { detectAnomalies } from '@/composables/useAnomalyDetection'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { formatDuration } from '@/utils/format'

const route = useRoute()
const manifestStore = useManifestStore()

const dut = computed(() => {
  const id = decodeURIComponent(route.params.dutId as string)
  return manifestStore.dutById(id)
})

const totalCollectors = computed(() => {
  if (!dut.value) return 0
  const s = dut.value.status_summary
  return s.success + s.error + s.partial + s.skipped
})

const successRate = computed(() => {
  if (!dut.value || totalCollectors.value === 0) return 0
  return (dut.value.status_summary.success / totalCollectors.value) * 100
})

const perfRank = computed(() => {
  if (!dut.value) return { timeRank: 0, sizeRank: 0 }
  const sorted = [...manifestStore.duts].sort((a, b) => a.execution_time - b.execution_time)
  const timeRank = sorted.findIndex(d => d.id === dut.value!.id) + 1
  const sizeSorted = [...manifestStore.duts].sort((a, b) => a.log_size - b.log_size)
  const sizeRank = sizeSorted.findIndex(d => d.id === dut.value!.id) + 1
  return { timeRank, sizeRank }
})

const dutAnomalies = computed(() => {
  if (!manifestStore.manifest || !dut.value) return []
  return detectAnomalies(manifestStore.manifest).filter(a => a.dutId === dut.value!.id)
})

const dutErrors = computed(() =>
  manifestStore.errors.filter(e => e.dut_id === dut.value?.id)
)

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}
</script>

<style scoped>
.dp-section {
  padding: 16px 20px;
  border-radius: var(--nv-radius-lg);
  margin-bottom: 12px;
}
.dp-section__title {
  font-size: 0.875rem;
  font-weight: 700;
  color: var(--nv-text-primary);
  margin: 0 0 12px;
}
.dp-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
}
.dp-field { display: flex; flex-direction: column; gap: 2px; }
.dp-field__label {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--nv-text-tertiary);
  font-weight: 600;
}
.dp-field__value {
  font-size: 0.8125rem;
  color: var(--nv-text-primary);
  font-weight: 500;
}
.dp-perf-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 10px;
}
.dp-perf {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 10px;
  background: var(--nv-glass-bg-light);
  border-radius: var(--nv-radius-md);
  border: 1px solid var(--nv-glass-border);
}
.dp-perf__value {
  font-size: 1.125rem;
  font-weight: 700;
  font-family: var(--nv-font-mono);
  color: var(--nv-text-primary);
}
.dp-perf__label {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--nv-text-tertiary);
  font-weight: 600;
}
.dp-perf__rank {
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
}
.dp-status-pill {
  display: inline-flex;
  padding: 3px 10px;
  border-radius: 10px;
  font-size: 0.6875rem;
  font-weight: 600;
  text-transform: capitalize;
}
.dp-status-pill--success { background: var(--nv-success-muted); color: var(--nv-success); }
.dp-status-pill--error { background: var(--nv-error-muted); color: var(--nv-error); }
.dp-status-pill--partial { background: var(--nv-warning-muted); color: var(--nv-warning); }
.dp-status-pill--skipped { background: var(--nv-glass-bg-light); color: var(--nv-text-tertiary); }
.dp-status-pill--not_ran { background: var(--nv-glass-bg-light); color: var(--nv-text-tertiary); }
.dp-fw-list { display: flex; flex-direction: column; gap: 4px; }
.dp-fw-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 4px 0;
  border-bottom: 1px solid var(--nv-glass-border);
  font-size: 0.75rem;
}
.dp-fw-item:last-child { border-bottom: none; }
.dp-fw-item__name { font-weight: 600; color: var(--nv-text-primary); min-width: 120px; }
.dp-fw-item__ver { font-family: var(--nv-font-mono); color: var(--nv-accent); }
.dp-fw-item__comp { color: var(--nv-text-tertiary); }
.dp-fw-item__date { color: var(--nv-text-tertiary); margin-left: auto; }
.dp-anomaly-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border-radius: var(--nv-radius-sm);
  transition: background var(--nv-duration-base) var(--nv-ease);
}
.dp-anomaly-row:hover { background: var(--nv-glass-bg-light); }
.ano-sev-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.ano-sev-dot--critical { background: var(--nv-error); }
.ano-sev-dot--warning { background: var(--nv-warning); }
.ano-sev-dot--info { background: var(--nv-info); }
</style>
