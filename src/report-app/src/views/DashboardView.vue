<template>
  <div class="nv-page" ref="dashboardRef">
    <PageLoader v-if="!manifestStore.loaded" message="Loading dashboard..." />

    <template v-else>
      <Breadcrumbs :items="[{ label: 'Dashboard' }]" />

      <h2 class="nv-page__title" style="margin: 16px 0 20px;">NVDebug Collection Report</h2>

      <!-- Executive Summary (visible in print, collapsible on screen) -->
      <div class="exec-summary nv-glass--elevated print-only-full">
        <div class="exec-summary__header">
          <div>
            <h3 style="margin: 0; font-size: 1rem; font-weight: 700;">Executive Summary</h3>
            <div style="font-size: 0.6875rem; color: var(--nv-text-tertiary); margin-top: 2px;">
              Generated {{ manifestStore.generatedAt }} | Tool v{{ manifestStore.toolVersion }}
            </div>
          </div>
          <div style="display: flex; gap: 6px; align-items: center;">
            <button class="exec-action-btn no-print" @click="printReport" title="Print report" aria-label="Print report">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>
                <rect x="6" y="14" width="12" height="8"/>
              </svg>
              <span>Print</span>
            </button>
            <button class="nv-btn nv-btn--sm nv-btn--primary no-print" :disabled="isExporting" @click="handlePdfExport" title="Export PDF">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none" style="margin-right: 4px;"><path d="M8 1v9M4 7l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 12v2h12v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
              {{ isExporting ? 'Exporting...' : 'Export PDF' }}
            </button>
          </div>
        </div>
        <div class="exec-summary__body">
          <div class="exec-summary__metric">
            <span class="exec-summary__metric-label">DUTs</span>
            <span class="exec-summary__metric-value">{{ summary?.total_duts ?? 0 }}</span>
          </div>
          <div class="exec-summary__metric">
            <span class="exec-summary__metric-label">Pass Rate</span>
            <span class="exec-summary__metric-value" :style="{ color: passRateColor }">{{ executedPassRate }}%</span>
          </div>
          <div class="exec-summary__metric">
            <span class="exec-summary__metric-label">Passed</span>
            <span class="exec-summary__metric-value" style="color: var(--nv-success);">{{ statusCounts.success }}</span>
          </div>
          <div class="exec-summary__metric">
            <span class="exec-summary__metric-label">Failed</span>
            <span class="exec-summary__metric-value" style="color: var(--nv-error);">{{ statusCounts.error }}</span>
          </div>
          <div class="exec-summary__metric">
            <span class="exec-summary__metric-label">Runtime</span>
            <span class="exec-summary__metric-value">{{ formatDuration(summary?.total_runtime ?? 0) }}</span>
          </div>
          <div class="exec-summary__metric">
            <span class="exec-summary__metric-label">Log Size</span>
            <span class="exec-summary__metric-value">{{ formatBytes(summary?.total_log_size ?? 0) }}</span>
          </div>
        </div>
      </div>

      <!-- Row 1: Executive Summary — 4 stat cards -->
      <div class="nv-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 16px;">
        <StatCard
          label="Total DUTs"
          :value="summary?.total_duts ?? 0"
          color="blue"
          :clickable="true"
          @click="showDutsModal = true"
        />
        <StatCard
          label="Total Log Size"
          :value="formatBytes(summary?.total_log_size ?? 0)"
          color="blue"
          :clickable="true"
          @click="showLogSizeModal = true"
        />
        <StatCard
          label="Overall Collection %"
          :value="executedPassRate + '%'"
          :subtitle="`${statusCounts.success} passed / ${executedCount} executed`"
          color="purple"
          :clickable="true"
          @click="router.push('/status/all')"
        />
        <StatCard
          label="Total Runtime"
          :value="formatDuration(summary?.total_runtime ?? 0)"
          color="green"
          :clickable="true"
          @click="router.push('/timing')"
        />
      </div>

      <!-- Row 2: Status stat cards — clickable to /status/{type} -->
      <div class="nv-grid" style="grid-template-columns: repeat(4, 1fr); margin-bottom: 16px;">
        <StatCard
          label="Passed Collectors"
          :value="statusCounts.success"
          :subtitle="`of ${executedCount} executed`"
          color="emerald"
          :clickable="true"
          @click="router.push('/status/success')"
        />
        <StatCard
          label="Failed Collectors"
          :value="statusCounts.error"
          :subtitle="`of ${executedCount} executed`"
          color="red"
          :clickable="true"
          @click="router.push('/status/error')"
        />
        <StatCard
          label="Partial Collectors"
          :value="statusCounts.partial"
          :subtitle="`of ${executedCount} executed`"
          color="amber"
          :clickable="true"
          @click="router.push('/status/partial')"
        />
        <StatCard
          label="Skipped Collectors"
          :value="statusCounts.skipped"
          :subtitle="`of ${executedCount} executed`"
          color="orange"
          :clickable="true"
          @click="router.push('/status/skipped')"
        />
      </div>

      <!-- Row 3: Progress bar + collection status -->
      <div class="nv-glass nv-glass--accent" style="padding: 16px 20px; margin-bottom: 16px;">
        <ProgressBar :counts="statusCounts" :exclude-not-ran="true" />
        <div style="margin-top: 8px; font-size: 0.75rem; color: var(--nv-text-secondary); display: flex; gap: 20px; flex-wrap: wrap;">
          <span>Executed: <strong>{{ executedCount }}</strong> collectors across <strong>{{ summary?.total_duts ?? 0 }}</strong> DUTs</span>
          <span v-if="notRanCount > 0">Not executed: <strong>{{ notRanCount }}</strong></span>
          <span v-if="(summary?.total_collectors_filtered_out ?? 0) > 0">Filtered out: <strong>{{ summary?.total_collectors_filtered_out }}</strong></span>
        </div>
      </div>

      <!-- Row 4: DUT Reports table (MOVED UP -- primary content) -->
      <div class="nv-glass" style="padding: 16px 20px; margin-bottom: 16px;">
        <h3 class="nv-section-title" style="margin-bottom: 12px;">DUT Reports</h3>
        <DataTable
          :columns="dutColumns"
          :data="dutTableData"
          :searchable="true"
          :fill-viewport="true"
          @row-click="(row: Record<string, any>) => router.push(`/dut/${row.id}`)"
        >
          <template #cell-report="{ row }">
            <router-link
              :to="`/dut/${row.id}`"
              class="nv-btn nv-btn--sm nv-btn--primary"
              style="font-size: 0.6875rem; padding: 2px 8px; text-decoration: none;"
              @click.stop
            >
              View Report
            </router-link>
          </template>
          <template #cell-status="{ value }">
            <StatusBadge :status="value" />
          </template>
          <template #cell-log_size="{ value }">
            {{ formatBytes(value) }}
          </template>
          <template #cell-execution_time="{ value }">
            {{ formatDuration(value) }}
          </template>
          <template #cell-system_fru="{ row }">
            <div style="font-size: 0.75rem; line-height: 1.5;">
              <div v-if="row.model">Model: {{ row.model }}</div>
              <div v-if="row.part_number">Partno: {{ row.part_number }}</div>
              <div v-if="row.serial_number">Serialno: {{ row.serial_number }}</div>
              <span v-if="!row.model && !row.part_number && !row.serial_number" style="color: var(--nv-text-tertiary);">&mdash;</span>
            </div>
          </template>
          <template #cell-system_view="{ row }">
            <button
              class="nv-btn nv-btn--sm nv-btn--primary"
              style="font-size: 0.6875rem; padding: 2px 8px;"
              @click.stop="showSystemViewForDut = row.id"
            >
              View
            </button>
          </template>
          <template #cell-firmware_summary="{ row }">
            <div style="font-size: 0.75rem;">
              <span v-if="row._fw_display">{{ row._fw_display }}</span>
              <span v-else style="color: var(--nv-text-tertiary);">&mdash;</span>
              <button
                v-if="row._fw_count > 0"
                class="nv-btn nv-btn--primary nv-btn--sm"
                style="font-size: 0.625rem; padding: 1px 6px; margin-left: 4px;"
                @click.stop="showFirmwareForDut = row.id"
              >
                Details
              </button>
            </div>
          </template>
        </DataTable>
      </div>

      <!-- Row 5: Quick Actions + Tool Config (compact, side by side) -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
        <QuickActions />
        <div class="nv-card">
          <h4 class="nv-section-title" style="margin-bottom: 8px;">Tool Configuration</h4>
          <div style="display: flex; gap: 16px; flex-wrap: wrap; font-size: 0.75rem;">
            <span v-if="toolConfig.collection_level"><strong>Level:</strong> {{ toolConfig.collection_level }}</span>
            <span v-if="toolConfig.baseboard"><strong>Baseboard:</strong> {{ toolConfig.baseboard }}</span>
            <span v-if="toolConfig.execution_mode"><strong>Execution:</strong> {{ toolConfig.execution_mode }}</span>
            <span><strong>Tool:</strong> v{{ manifestStore.toolVersion }}</span>
            <span><strong>Generated:</strong> {{ manifestStore.generatedAt }}</span>
          </div>
          <div style="margin-top: 12px;">
            <button class="nv-btn nv-btn--primary nv-btn--sm" @click="showSummary = true">
              Generate Summary
            </button>
          </div>
        </div>
      </div>

      <!-- Row 6: Anomalies (if any) -->
      <div v-if="anomalies.length > 0" class="nv-glass" style="padding: 14px 20px; margin-bottom: 16px;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
          <h3 class="nv-section-title" style="margin: 0;">
            Anomalies Detected
            <span style="font-size: 0.75rem; font-weight: 500; color: var(--nv-text-secondary); margin-left: 6px;">{{ anomalies.length }}</span>
          </h3>
          <div style="display: flex; align-items: center; gap: 8px; font-size: 0.6875rem;">
            <span v-if="anomalySummary.critical > 0" style="color: var(--nv-error); font-weight: 600;">{{ anomalySummary.critical }} critical</span>
            <span v-if="anomalySummary.warning > 0" style="color: var(--nv-warning); font-weight: 600;">{{ anomalySummary.warning }} warning</span>
            <span v-if="anomalySummary.info > 0" style="color: var(--nv-info); font-weight: 600;">{{ anomalySummary.info }} info</span>
            <router-link to="/anomalies" style="color: var(--nv-accent); font-weight: 600; font-size: 0.6875rem; text-decoration: none;">View All &rarr;</router-link>
          </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 6px; max-height: 200px; overflow-y: auto;">
          <div
            v-for="a in anomalies.slice(0, 8)"
            :key="a.id"
            class="anomaly-row"
            @click="router.push(`/dut/${encodeURIComponent(a.dutId)}`)"
          >
            <span :class="['ea-sev-dot', `ea-sev-dot--${a.severity}`]" style="width: 6px; height: 6px;"></span>
            <span style="font-size: 0.75rem; font-weight: 600; color: var(--nv-text-primary); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1;">{{ a.title }}</span>
            <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary); flex-shrink: 0;">{{ a.dutId }}</span>
          </div>
          <router-link v-if="anomalies.length > 8" to="/anomalies" style="display: block; font-size: 0.6875rem; color: var(--nv-accent); padding: 4px 0; text-decoration: none; font-weight: 600;">
            + {{ anomalies.length - 8 }} more anomalies &rarr;
          </router-link>
        </div>
      </div>

      <!-- Row 7: Charts — collapsible -->
      <details class="charts-section" open>
        <summary class="charts-section__header nv-glass--subtle">
          <h3 class="nv-section-title" style="margin: 0;">Charts &amp; Analytics</h3>
          <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">Click to collapse</span>
        </summary>
        <div class="nv-grid nv-grid--charts" style="margin-top: 12px;">
          <div class="nv-chart-card">
            <h4 class="nv-chart-card__title">Execution Status Summary</h4>
            <ChartFullscreenModal title="Status Distribution">
              <StatusPieChart :counts="executedStatusCounts" />
              <template #fullscreen>
                <StatusPieChart :counts="executedStatusCounts" />
              </template>
            </ChartFullscreenModal>
          </div>
          <div class="nv-chart-card">
            <h4 class="nv-chart-card__title">Execution Time per Node</h4>
            <ChartFullscreenModal title="Execution Time per Node">
              <ExecutionTimeChart :duts="manifestStore.duts" />
              <template #fullscreen>
                <ExecutionTimeChart :duts="manifestStore.duts" />
              </template>
            </ChartFullscreenModal>
          </div>
          <div class="nv-chart-card">
            <h4 class="nv-chart-card__title">Log Size per Node</h4>
            <ChartFullscreenModal title="Log Size per Node">
              <LogSizeChart :duts="manifestStore.duts.map(d => ({ id: d.id, log_size: d.log_size }))" />
              <template #fullscreen>
                <LogSizeChart :duts="manifestStore.duts.map(d => ({ id: d.id, log_size: d.log_size }))" />
              </template>
            </ChartFullscreenModal>
          </div>
        </div>
      </details>
    </template>

    <!-- DUTs Modal -->
    <ModalDialog v-model="showDutsModal" title="All DUTs" max-width="700px">
      <DataTable :columns="dutModalColumns" :data="dutTableData">
        <template #cell-status="{ value }">
          <StatusBadge :status="value" />
        </template>
        <template #cell-execution_time="{ value }">
          {{ formatDuration(value) }}
        </template>
        <template #cell-log_size="{ value }">
          {{ formatBytes(value) }}
        </template>
      </DataTable>
    </ModalDialog>

    <!-- Log Size Modal -->
    <ModalDialog v-model="showLogSizeModal" title="Log Size by DUT" max-width="500px">
      <DataTable
        :columns="[{ key: 'id', label: 'DUT' }, { key: 'log_size', label: 'Log Size' }]"
        :data="dutTableData"
      >
        <template #cell-log_size="{ value }">
          {{ formatBytes(value) }}
        </template>
      </DataTable>
    </ModalDialog>

    <!-- Firmware Modal -->
    <ModalDialog v-model="showFirmwareModal" :title="`Firmware — ${showFirmwareForDut}`" max-width="700px">
      <DataTable :columns="firmwareModalColumns" :data="firmwareModalData" />
    </ModalDialog>

    <!-- System View Modal -->
    <ModalDialog v-model="showSystemViewModal" :title="`System View - ${showSystemViewForDut}`" max-width="900px">
      <div class="system-view">
        <div class="system-view__grid">
          <section class="system-view__section">
            <h4>BMC</h4>
            <dl class="system-view__facts">
              <div><dt>Version</dt><dd>{{ displayValue(selectedSystemView?.bmc?.version) }}</dd></div>
              <div><dt>OS</dt><dd>{{ displayValue(selectedSystemView?.bmc?.os) }}</dd></div>
              <div><dt>Kernel</dt><dd>{{ displayValue(selectedSystemView?.bmc?.kernel) }}</dd></div>
              <div><dt>Uptime</dt><dd>{{ displayValue(selectedSystemView?.bmc?.uptime) }}</dd></div>
            </dl>
          </section>
          <section class="system-view__section">
            <h4>Host</h4>
            <dl class="system-view__facts">
              <div><dt>OS</dt><dd>{{ displayValue(selectedSystemView?.host?.os) }}</dd></div>
              <div><dt>Kernel</dt><dd>{{ displayValue(selectedSystemView?.host?.kernel) }}</dd></div>
              <div><dt>Uptime</dt><dd>{{ displayValue(selectedSystemView?.host?.uptime) }}</dd></div>
            </dl>
          </section>
        </div>

        <section class="system-view__section">
          <h4>System Utilization</h4>
          <table class="nv-table system-view__table">
            <thead>
              <tr>
                <th>Target</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Disk</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in systemViewUtilizationRows" :key="row.target">
                <td>{{ row.target }}</td>
                <td>{{ displayValue(row.cpu) }}</td>
                <td>{{ displayValue(row.memory) }}</td>
                <td>{{ displayValue(row.disk) }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section class="system-view__section">
          <h4>Device Under Test Software Information</h4>
          <table class="nv-table system-view__table">
            <tbody>
              <tr v-for="row in systemViewSoftwareRows" :key="row.label">
                <th>{{ row.label }}</th>
                <td>{{ displayValue(row.value) }}</td>
              </tr>
            </tbody>
          </table>
        </section>
      </div>
    </ModalDialog>

    <!-- Report Summary Modal -->
    <ModalDialog v-model="showSummary" title="Report Summary" max-width="700px">
      <pre class="nv-log__content" style="padding: 16px; border-radius: 8px;">{{ reportSummaryText }}</pre>
      <div style="margin-top: 12px; display: flex; gap: 8px;">
        <button class="nv-btn nv-btn--primary nv-btn--sm" @click="copySummary">Copy to Clipboard</button>
      </div>
    </ModalDialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import StatCard from '@/components/dashboard/StatCard.vue'
import ProgressBar from '@/components/dashboard/ProgressBar.vue'
import QuickActions from '@/components/dashboard/QuickActions.vue'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ModalDialog from '@/components/common/ModalDialog.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import StatusPieChart from '@/components/charts/StatusPieChart.vue'
import LogSizeChart from '@/components/charts/LogSizeChart.vue'
import ExecutionTimeChart from '@/components/charts/ExecutionTimeChart.vue'
import ChartFullscreenModal from '@/components/charts/ChartFullscreenModal.vue'
import { generateReportSummary } from '@/composables/useReportSummary'
import { detectAnomalies, getAnomalySummary } from '@/composables/useAnomalyDetection'
import { showToast } from '@/composables/useToast'
import { copyToClipboard } from '@/utils/clipboard'
import { formatDuration } from '@/utils/format'
import { usePdfExport } from '@/composables/usePdfExport'

interface Column {
  key: string
  label: string
  sortable?: boolean
}

const manifestStore = useManifestStore()
const router = useRouter()
const dashboardRef = ref<HTMLElement>()
const { exportToPdf, isExporting } = usePdfExport()

const showDutsModal = ref(false)
const showLogSizeModal = ref(false)
const showSummary = ref(false)
const showFirmwareForDut = ref('')
const showSystemViewForDut = ref('')

const showFirmwareModal = computed({
  get: () => showFirmwareForDut.value !== '',
  set: (v: boolean) => { if (!v) showFirmwareForDut.value = '' },
})

const showSystemViewModal = computed({
  get: () => showSystemViewForDut.value !== '',
  set: (v: boolean) => { if (!v) showSystemViewForDut.value = '' },
})

const reportSummaryText = computed(() => manifestStore.manifest ? generateReportSummary(manifestStore.manifest) : '')

const anomalies = computed(() => manifestStore.manifest ? detectAnomalies(manifestStore.manifest) : [])
const anomalySummary = computed(() => getAnomalySummary(anomalies.value))

async function copySummary() {
  try {
    await copyToClipboard(reportSummaryText.value)
    showToast('Copied to clipboard', 'success')
  } catch {
    showToast('Copy failed', 'error')
  }
}

function printReport() {
  window.print()
}

async function handlePdfExport() {
  if (!dashboardRef.value) return
  const ts = manifestStore.manifest?.generated_at?.replace(/[\s:]/g, '-') ?? 'report'
  await exportToPdf(dashboardRef.value, `nvdebug-report-${ts}.pdf`)
}

const summary = computed(() => manifestStore.collectionSummary)
const toolConfig = computed(() => {
  const cfg = manifestStore.manifest?.tool_config
  const level = cfg?.collection_level
  const mode = cfg?.execution_mode
  const board = cfg?.baseboard
  return {
    collection_level: level && level !== 'unknown' ? String(level) : '',
    execution_mode: mode && mode !== 'unknown' ? String(mode) : '',
    baseboard: board && board !== 'unknown' ? String(board) : '',
  }
})
const statusCounts = computed(() => manifestStore.globalStatusCounts)
const executedCount = computed(() => {
  const s = statusCounts.value
  return s.success + s.error + s.partial + s.skipped
})
const notRanCount = computed(() => statusCounts.value.not_ran ?? 0)
const executedStatusCounts = computed(() => {
  const { not_ran, ...rest } = statusCounts.value
  return rest as Record<string, number>
})
const totalCollectors = computed(() =>
  Object.values(statusCounts.value).reduce((a, b) => a + b, 0)
)
const executedPassRate = computed(() => {
  if (executedCount.value === 0) return 0
  return Math.round((statusCounts.value.success / executedCount.value) * 100)
})
const passRateColor = computed(() => {
  const pct = executedPassRate.value
  if (pct >= 90) return 'var(--nv-success)'
  if (pct >= 70) return 'var(--nv-warning)'
  return 'var(--nv-error)'
})

const dutColumns: Column[] = [
  { key: 'id', label: 'Node Name', sortable: true },
  { key: 'report', label: 'Report', sortable: false },
  { key: 'execution_time', label: 'Log Collection Time', sortable: true },
  { key: 'system_fru', label: 'System FRU', sortable: false },
  { key: 'system_view', label: 'System View', sortable: false },
  { key: 'firmware_summary', label: 'System Firmware', sortable: false },
  { key: 'log_size', label: 'Total Log Size', sortable: true },
]

const dutModalColumns: Column[] = [
  { key: 'id', label: 'DUT' },
  { key: 'status', label: 'Status' },
  { key: 'execution_time', label: 'Time' },
  { key: 'log_size', label: 'Size' },
]

function buildFirmwareSummary(fw: any[]): string {
  if (!fw || fw.length === 0) return ''
  const bmc = fw.find((f: any) => /^bmc/i.test(f.name || f.id || ''))
  const hmc = fw.find((f: any) => /^hmc/i.test(f.name || f.id || ''))
  const gpu = fw.filter((f: any) => /gpu/i.test(f.name || f.id || ''))
  const parts: string[] = []
  if (bmc) parts.push(`BMC: ${bmc.version || '?'}`)
  if (hmc) parts.push(`HMC: ${hmc.version || '?'}`)
  if (gpu.length === 1) parts.push(`GPU: ${gpu[0].version || '?'}`)
  else if (gpu.length > 1) parts.push('GPU: Multiple versions')
  if (parts.length === 0) parts.push(`${fw.length} component${fw.length > 1 ? 's' : ''}`)
  return parts.join(', ')
}

const dutTableData = computed(() =>
  manifestStore.duts.map(dut => {
    const fw = dut.system_info?.firmware ?? []
    return {
      id: dut.id,
      status: dut.overall_status,
      execution_time: dut.execution_time,
      model: dut.system_info?.model ?? '',
      part_number: dut.system_info?.part_number ?? '',
      serial_number: dut.system_info?.serial_number ?? '',
      system_fru: `${dut.system_info?.model ?? ''} ${dut.system_info?.part_number ?? ''}`.trim(),
      system_view: 'View',
      firmware_summary: buildFirmwareSummary(fw),
      _fw_display: buildFirmwareSummary(fw),
      _fw_count: fw.length,
      log_size: dut.log_size,
    }
  })
)

const firmwareModalColumns: Column[] = [
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  { key: 'version', label: 'Version' },
]

const firmwareModalData = computed(() => {
  if (!showFirmwareForDut.value) return []
  const dut = manifestStore.dutById(showFirmwareForDut.value)
  return (dut?.system_info?.firmware ?? []).map((f: any) => ({
    id: f.id || f.component || '\u2014',
    name: f.name || f.id || f.component || '\u2014',
    version: f.version || '\u2014',
  }))
})

const selectedSystemView = computed(() => {
  if (!showSystemViewForDut.value) return null
  return manifestStore.dutById(showSystemViewForDut.value)?.system_info?.system_view ?? null
})

const systemViewUtilizationRows = computed(() => [
  {
    target: 'BMC',
    cpu: selectedSystemView.value?.bmc?.utilization?.cpu,
    memory: selectedSystemView.value?.bmc?.utilization?.memory,
    disk: selectedSystemView.value?.bmc?.utilization?.disk,
  },
  {
    target: 'Host',
    cpu: selectedSystemView.value?.host?.utilization?.cpu,
    memory: selectedSystemView.value?.host?.utilization?.memory,
    disk: selectedSystemView.value?.host?.utilization?.disk,
  },
])

const systemViewSoftwareRows = computed(() => [
  { label: 'Host OS', value: selectedSystemView.value?.software?.host_os },
  { label: 'Kernel Version', value: selectedSystemView.value?.software?.kernel_version },
  { label: 'BMC Version', value: selectedSystemView.value?.software?.bmc_version },
  { label: 'SBIOS', value: selectedSystemView.value?.software?.sbios },
  { label: 'RM Driver Version', value: selectedSystemView.value?.software?.rm_driver_version },
  { label: 'CUDA Driver Version', value: selectedSystemView.value?.software?.cuda_driver_version },
  { label: 'DCGM Version', value: selectedSystemView.value?.software?.dcgm_version },
])

function displayValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Not collected'
  return String(value)
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i]
}

</script>

<style scoped>
.charts-section {
  margin-bottom: 16px;
}
.charts-section__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-radius: var(--nv-radius-lg);
  cursor: pointer;
  list-style: none;
  user-select: none;
}
.charts-section__header::-webkit-details-marker {
  display: none;
}
.charts-section[open] .charts-section__header span:last-child {
  content: 'Click to collapse';
}
/* ── Executive Summary ── */
.exec-summary {
  padding: 16px 20px;
  border-radius: var(--nv-radius-lg);
  margin-bottom: 16px;
}
.exec-summary__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 14px;
}
.exec-summary__body {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
}
.exec-summary__metric {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 10px 8px;
  background: var(--nv-glass-bg-light);
  border-radius: var(--nv-radius-md);
  border: 1px solid var(--nv-glass-border);
}
.exec-summary__metric-label {
  font-size: 0.625rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--nv-text-tertiary);
  font-weight: 600;
}
.exec-summary__metric-value {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--nv-text-primary);
  font-family: var(--nv-font-mono);
}
@media (max-width: 768px) {
  .exec-summary__body { grid-template-columns: repeat(3, 1fr); }
}

.anomaly-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border-radius: var(--nv-radius-sm);
  cursor: pointer;
  transition: background var(--nv-duration-base) var(--nv-ease);
}
.anomaly-row:hover {
  background: var(--nv-glass-bg-light);
}
.ea-sev-dot {
  border-radius: 50%;
  flex-shrink: 0;
}
.ea-sev-dot--critical { background: var(--nv-error); }
.ea-sev-dot--warning { background: var(--nv-warning); }
.ea-sev-dot--info { background: var(--nv-info); }

.charts-section:not([open]) .charts-section__header span:last-child::after {
  content: ' (collapsed)';
}

/* Executive summary action buttons */
.exec-action-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 10px;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-sm);
  background: none;
  color: var(--nv-text-secondary);
  font: inherit;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
}
.exec-action-btn:hover {
  background: var(--nv-bg-tertiary);
  color: var(--nv-text-primary);
  border-color: var(--nv-accent);
}
.exec-action-btn:active {
  transform: scale(0.97);
}

.system-view {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.system-view__grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.system-view__section {
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  padding: 12px;
  background: var(--nv-glass-bg-light);
}
.system-view__section h4 {
  margin: 0 0 10px;
  font-size: 0.875rem;
  color: var(--nv-text-primary);
}
.system-view__facts {
  display: grid;
  gap: 8px;
  margin: 0;
}
.system-view__facts div {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  gap: 12px;
}
.system-view__facts dt,
.system-view__table th {
  color: var(--nv-text-tertiary);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}
.system-view__facts dd {
  margin: 0;
  color: var(--nv-text-primary);
  font-size: 0.8125rem;
  word-break: break-word;
}
.system-view__table {
  width: 100%;
}
.system-view__table td,
.system-view__table th {
  font-size: 0.8125rem;
  word-break: break-word;
}
@media (max-width: 768px) {
  .system-view__grid {
    grid-template-columns: 1fr;
  }
  .system-view__facts div {
    grid-template-columns: 1fr;
    gap: 2px;
  }
}
</style>
