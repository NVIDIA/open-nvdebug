<template>
  <div ref="dutViewRef" style="min-height: calc(100vh - 88px);">
    <!-- Left Sidebar -->
    <div class="nv-sidebar">
      <div class="nv-sidebar__section">
        <h3 class="nv-page__title" style="font-size: 1rem; margin-bottom: 4px;">Node: {{ dut?.id }}</h3>
        <StatusBadge v-if="dut" :status="dut.overall_status" />
        <div style="margin-top: 4px; font-size: 0.75rem; color: var(--nv-text-secondary);">
          Total execution time: {{ formatDuration(dut?.execution_time ?? 0) }}
        </div>
      </div>

      <div v-if="dut?.system_info" class="nv-sidebar__section" style="font-size: 0.75rem;">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">System Details</h4>
        <div v-if="dut.system_info.model"><strong>Model:</strong> {{ dut.system_info.model }}</div>
        <div v-if="dut.system_info.part_number"><strong>Partno:</strong> {{ dut.system_info.part_number }}</div>
        <div v-if="dut.system_info.serial_number"><strong>Serialno:</strong> {{ dut.system_info.serial_number }}</div>
      </div>

      <div class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">Collector Groups</h4>
        <div v-for="group in dut?.collector_groups" :key="group.name" style="margin-bottom: 4px;">
          <router-link :to="`/dut/${dutId}/${group.name}`" class="nv-sidebar__link">
            <ServiceBadge :service="group.name" />
          </router-link>
        </div>
      </div>

      <div v-if="metadataFiles.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">Node Metadata Files</h4>
        <router-link
          v-for="f in metadataFiles"
          :key="f.path"
          :to="`/file/${encodeURIComponent(f.path)}`"
          class="nv-sidebar__link"
          style="font-size: 0.6875rem;"
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M1.5 0.5h4l2.5 2.5v6h-6.5v-8.5z" stroke="currentColor" stroke-width="0.5"/></svg>
          {{ f.path.split('/').pop() }}
        </router-link>
      </div>

      <div v-if="configFiles.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">Node Config</h4>
        <router-link
          v-for="f in configFiles"
          :key="f.path"
          :to="`/file/${encodeURIComponent(f.path)}`"
          class="nv-sidebar__link"
          style="font-size: 0.6875rem;"
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M1.5 0.5h4l2.5 2.5v6h-6.5v-8.5z" stroke="currentColor" stroke-width="0.5"/></svg>
          {{ f.path.split('/').pop() }}
        </router-link>
      </div>

      <div v-if="runtimeLogFiles.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">Runtime Logs</h4>
        <router-link
          v-for="f in runtimeLogFiles"
          :key="f.path"
          :to="`/file/${encodeURIComponent(f.path)}`"
          class="nv-sidebar__link"
          style="font-size: 0.6875rem;"
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M1.5 0.5h4l2.5 2.5v6h-6.5v-8.5z" stroke="currentColor" stroke-width="0.5"/></svg>
          {{ f.path.split('/').pop() }}
        </router-link>
      </div>

      <div v-if="errorLogFiles.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">Error Logs</h4>
        <router-link
          v-for="f in errorLogFiles"
          :key="f.path"
          :to="`/file/${encodeURIComponent(f.path)}`"
          class="nv-sidebar__link"
          style="font-size: 0.6875rem; color: var(--nv-error);"
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M5 1L9 9H1L5 1z" stroke="currentColor" stroke-width="0.5"/></svg>
          {{ f.path.split('/').pop() }}
        </router-link>
      </div>

      <div v-if="fileCategories.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">File Categories</h4>
        <details v-for="cat in fileCategories" :key="cat.name" style="margin-bottom: 2px;">
          <summary class="nv-sidebar__link" style="cursor: pointer; list-style: none;">
            {{ cat.name }} <span class="nv-badge nv-badge--neutral" style="margin-left: auto;">{{ cat.files.length }}</span>
          </summary>
          <div style="padding-left: 16px;">
            <router-link
              v-for="f in cat.files.slice(0, 20)"
              :key="f.path"
              :to="`/file/${encodeURIComponent(f.path)}`"
              class="nv-sidebar__link"
              style="font-size: 0.6875rem;"
            >{{ f.path.split('/').pop() }}</router-link>
            <div v-if="cat.files.length > 20" style="font-size: 0.6875rem; color: var(--nv-text-tertiary); padding: 2px 0;">
              +{{ cat.files.length - 20 }} more
            </div>
          </div>
        </details>
      </div>
    </div>

    <!-- Main Content -->
    <div class="nv-page" style="margin-left: 260px;">
      <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: dut?.id ?? dutId }]" />
      <div style="display: flex; align-items: center; justify-content: space-between; margin: 12px 0 16px;">
        <h2 class="nv-page__title" style="margin: 0;">Node Report: {{ dut?.id }}</h2>
        <button class="nv-btn nv-btn--sm nv-btn--ghost no-print" :disabled="isExporting" @click="handleDutPdf" title="Export PDF">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" style="margin-right: 4px;"><path d="M8 1v9M4 7l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M2 12v2h12v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          {{ isExporting ? 'Exporting...' : 'Export PDF' }}
        </button>
      </div>

      <!-- Status Summary -->
      <div v-if="dut" class="nv-glass--subtle" style="margin-bottom: 16px; padding: 12px 16px; border-radius: var(--nv-radius-lg);">
        <ProgressBar :counts="dut.status_summary" :exclude-not-ran="!showNotRan" />
      </div>

      <!-- Preflight Checks — Compact Scalable Table -->
      <div v-if="allPreflightChecks.length > 0" class="nv-card" style="margin-bottom: 16px;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
          <h4 class="nv-chart-card__title" style="margin-bottom: 0;">
            Preflight Checks
            <span class="nv-badge" :class="allPreflightPassed ? 'nv-badge--success' : 'nv-badge--error'" style="margin-left: 8px;">
              {{ preflightPassCount }}/{{ allPreflightChecks.length }} passed
            </span>
          </h4>
          <router-link :to="`/dut/${dutId}/preflight`" class="nv-btn nv-btn--ghost nv-btn--sm" style="text-decoration: none;">
            View All
          </router-link>
        </div>

        <!-- Service summary row (clickable chips) -->
        <div class="preflight-summary">
          <button
            v-for="svc in preflightByService"
            :key="svc.name"
            class="preflight-chip"
            :class="preflightChipClass(svc.status)"
            @click="openPreflightModal(svc)"
          >
            <span class="preflight-chip__icon">
              <span v-if="isPreflightPass(svc.status)">&#10004;</span>
              <span v-else-if="isPreflightFail(svc.status)">&#10008;</span>
              <span v-else>&#8212;</span>
            </span>
            <span class="preflight-chip__label">{{ svc.label }}</span>
            <span v-if="svc.count > 1" class="preflight-chip__count">{{ svc.passCount }}/{{ svc.count }}</span>
          </button>
        </div>

        <!-- Failed checks summary (clickable) -->
        <div v-if="preflightFailures.length > 0" style="margin-top: 12px;">
          <button class="preflight-failures-toggle" @click="openPreflightModal(null)">
            <span style="color: var(--nv-error); font-weight: 600;">{{ preflightFailures.length }} failed check{{ preflightFailures.length !== 1 ? 's' : '' }}</span>
            <span style="color: var(--nv-text-tertiary); font-size: 0.6875rem; margin-left: 8px;">Click to view details</span>
          </button>
        </div>
      </div>

      <!-- Dependencies -->
      <div v-if="dependencyChecks.length > 0" class="nv-card" style="margin-bottom: 16px;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <h4 class="nv-chart-card__title" style="margin-bottom: 0;">
            Dependencies
            <span v-if="collectorsWithDeps.length > 0" class="nv-badge nv-badge--neutral" style="margin-left: 8px;">{{ collectorsWithDeps.length }} collectors</span>
            <span v-else class="nv-badge nv-badge--neutral" style="margin-left: 8px;">{{ dependencyChecks.length }} checked</span>
          </h4>
          <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="depsModalOpen = true">View Details</button>
        </div>
        <template v-if="collectorsWithDeps.length > 0">
          <div class="deps-chip-list">
            <button
              v-for="dep in collectorsWithDeps.slice(0, 8)"
              :key="dep.collector_id"
              class="deps-chip"
              @click="openDepDetail(dep)"
            >
              <span class="deps-chip__id">{{ dep.collector_id }}</span>
              <span class="deps-chip__arrow">&#8594;</span>
              <span class="deps-chip__count">{{ depCount(dep) }} dep{{ depCount(dep) !== 1 ? 's' : '' }}</span>
            </button>
            <button
              v-if="collectorsWithDeps.length > 8"
              class="deps-chip deps-chip--more"
              @click="depsModalOpen = true"
            >+{{ collectorsWithDeps.length - 8 }} more</button>
          </div>
        </template>
        <div v-else style="margin-top: 10px; font-size: 0.8125rem; color: var(--nv-text-secondary);">
          No dependency requirements found across {{ dependencyChecks.length }} checked collector{{ dependencyChecks.length !== 1 ? 's' : '' }}. All collectors ran independently.
        </div>
      </div>

      <!-- Table controls: group filter tabs + not-ran toggle -->
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
        <div class="nv-tabs" style="margin-bottom: 0; border-bottom: none;">
          <button
            @click="groupFilter = ''"
            :class="['nv-tab', { 'nv-tab--active': groupFilter === '' }]"
          >All</button>
          <button
            v-for="group in dut?.collector_groups"
            :key="group.name"
            @click="groupFilter = group.name"
            :class="['nv-tab', { 'nv-tab--active': groupFilter === group.name }]"
          >{{ group.name }}</button>
        </div>

        <label v-if="notRanCount > 0" class="not-ran-toggle">
          <input type="checkbox" v-model="showNotRan" class="not-ran-toggle__input" />
          <span class="not-ran-toggle__label">
            Show not executed
            <span class="nv-badge nv-badge--neutral">{{ notRanCount }} not ran</span>
          </span>
        </label>
      </div>

      <!-- Execution Summary Table -->
      <h3 class="nv-section-title" style="margin-bottom: 8px;">Execution Summary</h3>
      <div class="nv-table-viewport">
        <DataTable
          :columns="collectorColumns"
          :data="visibleCollectors"
          :searchable="true"
          :fill-viewport="true"
          @row-click="onCollectorClick"
        >
          <template #cell-group="{ value }">
            <ServiceBadge :service="value" />
          </template>
          <template #cell-status="{ value }">
            <StatusBadge :status="value" />
          </template>
          <template #cell-execution_time="{ value }">
            {{ formatDuration(value) }}
          </template>
          <template #cell-log_size="{ value }">
            {{ formatBytes(value) }}
          </template>
          <template #cell-files="{ row }">
            <template v-if="row._files && row._files.length > 0">
              <div class="file-cell">
                <div v-for="f in sortedLogFiles(row._files).slice(0, 3)" :key="f.path" class="file-cell__item">
                  <span :class="['file-type-badge', `file-type-badge--${f.type || 'text'}`]">{{ (f.type || 'text').toUpperCase() }}</span>
                  <router-link
                    :to="`/file/${encodeURIComponent(f.path)}`"
                    class="file-cell__link"
                    @click.stop
                  >{{ f.path.split('/').pop() }}</router-link>
                </div>
                <button
                  v-if="row._files.length > 3"
                  class="nv-btn nv-btn--ghost nv-btn--sm"
                  style="font-size: 0.625rem; padding: 1px 6px; margin-top: 2px;"
                  @click.stop="showFilesModal(row)"
                >+{{ row._files.length - 3 }} more</button>
              </div>
            </template>
            <span v-else style="color: var(--nv-text-tertiary);">&mdash;</span>
          </template>
        </DataTable>
      </div>
    </div>

    <!-- Files Modal (enhanced: grouped by type, sorted alphabetically) -->
    <ModalDialog v-model="filesModalOpen" :title="`Files — ${filesModalCollector}`" max-width="750px">
      <div class="files-modal">
        <template v-for="group in filesModalGrouped" :key="group.label">
          <div class="files-modal__group-header">
            <span :class="['file-type-badge', `file-type-badge--${group.type}`]">{{ group.type.toUpperCase() }}</span>
            {{ group.label }}
            <span class="files-modal__group-count">{{ group.files.length }}</span>
          </div>
          <router-link
            v-for="f in group.files"
            :key="f.path"
            :to="`/file/${encodeURIComponent(f.path)}`"
            class="files-modal__item nv-sidebar__link"
            @click="filesModalOpen = false"
          >
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 1h5l3 3v7H2V1z" stroke="currentColor" stroke-width="1"/></svg>
            <span class="files-modal__name">{{ f.path.split('/').pop() }}</span>
            <span v-if="isDiagnosticFile(f)" class="files-modal__badge files-modal__badge--diag">diagnostic</span>
            <span class="files-modal__size">{{ formatBytes(f.size || 0) }}</span>
          </router-link>
        </template>
        <div v-if="filesModalData.length === 0" style="padding: 16px; text-align: center; color: var(--nv-text-tertiary);">No files</div>
      </div>
    </ModalDialog>

    <!-- Dependencies Modal (full table with status icons) -->
    <ModalDialog v-model="depsModalOpen" title="Collector Dependency Checks" max-width="900px">
      <DependencyTable v-if="collectorsWithDeps.length > 0" :collectors="collectorsWithDeps" />
      <div v-else style="padding: 16px 0;">
        <div style="font-size: 0.875rem; color: var(--nv-text-secondary); margin-bottom: 16px;">
          No dependency requirements found. All {{ dependencyChecks.length }} checked collectors ran independently.
        </div>
        <div class="nv-table-viewport" style="max-height: 400px;">
          <table class="nv-table">
            <thead>
              <tr>
                <th>Collector ID</th>
                <th>Collector Name</th>
                <th>Dependencies</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="c in dependencyChecks" :key="c.collector_id">
                <td style="font-weight: 600; font-family: var(--nv-font-mono);">{{ c.collector_id }}</td>
                <td>{{ c.name }}</td>
                <td style="color: var(--nv-text-tertiary);">None</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </ModalDialog>

    <!-- Single Dependency Detail Modal -->
    <ModalDialog v-model="depDetailOpen" :title="`Dependencies — ${depDetailCollector}`" max-width="900px">
      <DependencyTable v-if="depDetailData" :collectors="[depDetailData]" />
    </ModalDialog>

    <!-- Preflight Service Detail Modal -->
    <ModalDialog v-model="preflightModalOpen" :title="preflightModalTitle" max-width="800px">
      <div v-if="preflightModalChecks.length > 0" class="nv-table-viewport" style="max-height: 500px;">
        <table class="nv-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>Check</th>
              <th>Status</th>
              <th style="min-width: 200px;">Details</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(chk, i) in preflightModalChecks" :key="i">
              <td><ServiceBadge :service="chk.group || chk.name || ''" /></td>
              <td style="font-size: 0.75rem;">{{ chk.name || chk.check || '\u2014' }}</td>
              <td><StatusBadge :status="chk.status" /></td>
              <td style="font-size: 0.6875rem; max-width: 400px; word-break: break-word; color: var(--nv-text-secondary);">
                {{ chk.details || chk.reason || '\u2014' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else style="padding: 24px; text-align: center; color: var(--nv-text-tertiary); font-size: var(--nv-text-sm);">
        No checks found for this service.
      </div>
      <div style="margin-top: 12px; display: flex; align-items: center; gap: 12px; font-size: 0.6875rem; color: var(--nv-text-tertiary);">
        <span v-if="preflightModalPassCount > 0" style="color: var(--nv-success);">&#10004; {{ preflightModalPassCount }} passed</span>
        <span v-if="preflightModalFailCount > 0" style="color: var(--nv-error);">&#10008; {{ preflightModalFailCount }} failed</span>
        <span v-if="preflightModalNaCount > 0">&#8212; {{ preflightModalNaCount }} not ran</span>
        <span style="margin-left: auto;">
          <router-link :to="`/dut/${dutId}/preflight`" class="nv-btn nv-btn--ghost nv-btn--sm" style="text-decoration: none; font-size: 0.6875rem;" @click="preflightModalOpen = false">
            View Full Preflight Report
          </router-link>
        </span>
      </div>
    </ModalDialog>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { formatDuration } from '@/utils/format'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import ProgressBar from '@/components/dashboard/ProgressBar.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import ModalDialog from '@/components/common/ModalDialog.vue'
import DependencyTable from '@/components/common/DependencyTable.vue'
import { usePdfExport } from '@/composables/usePdfExport'
import { dedupFiles } from '@/utils/dedupFiles'

const route = useRoute()
const router = useRouter()
const manifestStore = useManifestStore()
const dutViewRef = ref<HTMLElement>()
const { exportToPdf, isExporting } = usePdfExport()

const dutId = computed(() => String(route.params.dutId))
const dut = computed(() => manifestStore.dutById(dutId.value))
const groupFilter = ref('')
const showNotRan = ref(false)

const filesModalOpen = ref(false)
const filesModalCollector = ref('')
const filesModalData = ref<any[]>([])

const depsModalOpen = ref(false)
const depDetailOpen = ref(false)
const depDetailCollector = ref('')
const depDetailData = ref<any>(null)

const preflightModalOpen = ref(false)
const preflightModalTitle = ref('Preflight Checks')
const preflightModalChecks = ref<any[]>([])

function openPreflightModal(svc: PreflightServiceSummary | null) {
  if (svc) {
    const key = svc.name.toLowerCase()
    preflightModalTitle.value = `Preflight — ${svc.label.toUpperCase()}`
    preflightModalChecks.value = (allPreflightChecks.value as any[]).filter(
      (c: any) => (c.group || c.name || '').toLowerCase() === key
    )
  } else {
    preflightModalTitle.value = 'Failed Preflight Checks'
    preflightModalChecks.value = preflightFailures.value
  }
  preflightModalOpen.value = true
}

const preflightModalPassCount = computed(() =>
  preflightModalChecks.value.filter((c: any) => isPreflightPass(c.status ?? '')).length
)
const preflightModalFailCount = computed(() =>
  preflightModalChecks.value.filter((c: any) => isPreflightFail(c.status ?? '')).length
)
const preflightModalNaCount = computed(() =>
  preflightModalChecks.value.length - preflightModalPassCount.value - preflightModalFailCount.value
)

async function handleDutPdf() {
  if (!dutViewRef.value) return
  await exportToPdf(dutViewRef.value, `nvdebug-${dutId.value}.pdf`)
}

// --- File sorting & categorization helpers ---

const FILE_TYPE_ORDER: Record<string, number> = {
  log: 0, text: 1, xml: 2, yaml: 3, json: 4, binary: 5,
}

function isDiagnosticFile(f: any): boolean {
  const name = (f.path?.split('/').pop() ?? '').toLowerCase()
  return /^(request|response|status|diagnostic)/.test(name) && name.endsWith('.json')
}

function sortedLogFiles(files: any[]): any[] {
  return [...files].sort((a, b) => {
    const aDiag = isDiagnosticFile(a) ? 1 : 0
    const bDiag = isDiagnosticFile(b) ? 1 : 0
    if (aDiag !== bDiag) return aDiag - bDiag
    const aOrd = FILE_TYPE_ORDER[a.type ?? 'text'] ?? 2
    const bOrd = FILE_TYPE_ORDER[b.type ?? 'text'] ?? 2
    if (aOrd !== bOrd) return aOrd - bOrd
    const aName = a.path?.split('/').pop() ?? ''
    const bName = b.path?.split('/').pop() ?? ''
    return aName.localeCompare(bName)
  })
}

interface FileGroup {
  type: string
  label: string
  files: any[]
}

const filesModalGrouped = computed((): FileGroup[] => {
  const grouped = new Map<string, any[]>()
  const sorted = sortedLogFiles(filesModalData.value)
  for (const f of sorted) {
    const t = f.type || 'text'
    if (!grouped.has(t)) grouped.set(t, [])
    grouped.get(t)!.push(f)
  }
  const TYPE_LABELS: Record<string, string> = {
    log: 'Log Files', text: 'Text Files', json: 'JSON Files',
    xml: 'XML Files', yaml: 'YAML Files', binary: 'Binary Files',
  }
  const groups: FileGroup[] = []
  for (const [type, files] of grouped) {
    const logFiles = files.filter(f => !isDiagnosticFile(f))
    const diagFiles = files.filter(f => isDiagnosticFile(f))
    if (logFiles.length > 0) {
      groups.push({ type, label: TYPE_LABELS[type] ?? `${type} Files`, files: logFiles })
    }
    if (diagFiles.length > 0) {
      groups.push({ type: 'json', label: 'Diagnostic / Request-Response', files: diagFiles })
    }
  }
  return groups
})

function showFilesModal(row: any) {
  filesModalCollector.value = `${row.id} — ${row.name}`
  filesModalData.value = row._files ?? []
  filesModalOpen.value = true
}

// --- Dependencies helpers ---

const dependencyChecks = computed(() => {
  const deps = manifestStore.manifest?.dependency_check?.per_dut ?? []
  const dutDeps = deps.find((d: any) => d.dut_id === dutId.value)
  return dutDeps?.collectors ?? []
})

const collectorsWithDeps = computed(() =>
  (dependencyChecks.value as any[]).filter((d: any) => d.dependencies && d.dependencies.length > 0)
)

function depCount(dep: any): number {
  return Array.isArray(dep.dependencies) ? dep.dependencies.length : 0
}

function openDepDetail(dep: any) {
  depDetailCollector.value = dep.collector_id
  depDetailData.value = dep
  depDetailOpen.value = true
}

// --- Table columns & data ---

interface Column { key: string; label: string; sortable?: boolean; formatter?: (value: unknown, row: Record<string, unknown>) => string }

const collectorColumns: Column[] = [
  { key: 'group', label: 'Collector Group' },
  { key: 'id', label: 'Collector ID' },
  { key: 'name', label: 'Collector Name' },
  { key: 'execution_time', label: 'Collector Exec Time', sortable: true, formatter: value => formatDuration(Number(value ?? 0)) },
  { key: 'status', label: 'Execution Status' },
  { key: 'log_size', label: 'Log Size', sortable: true, formatter: value => formatBytes(Number(value ?? 0)) },
  { key: 'files', label: 'Log Path(s)', sortable: false },
]

const allCollectors = computed(() => {
  if (!dut.value) return []
  const groups = groupFilter.value
    ? dut.value.collector_groups.filter(g => g.name === groupFilter.value)
    : dut.value.collector_groups
  return groups.flatMap(g =>
    g.collectors.map(c => {
      const uniqueFiles = dedupFiles(c.files)
      return {
        group: g.name,
        id: c.id,
        name: c.name,
        execution_time: c.execution_time,
        status: c.status,
        log_size: uniqueFiles.reduce((sum, f) => sum + (f.size || 0), 0),
        files: uniqueFiles.length,
        _files: uniqueFiles,
        _collectorId: c.id,
        _group: g.name,
      }
    })
  )
})

const notRanCount = computed(() =>
  allCollectors.value.filter(c => String(c.status) === 'not_ran' || String(c.status) === 'not ran').length
)

const visibleCollectors = computed(() => {
  if (showNotRan.value) return allCollectors.value
  return allCollectors.value.filter(c => String(c.status) !== 'not_ran' && String(c.status) !== 'not ran')
})

const dutFiles = computed(() =>
  manifestStore.fileIndex.filter(f => f.dut_id === dutId.value)
)

const metadataFiles = computed(() =>
  dutFiles.value.filter(f => {
    const parts = f.path.split('/')
    return parts.length >= 3 && (parts[1] === '.metadata' || parts[1] === 'metadata') && f.path.endsWith('.json')
  })
)

const configFiles = computed(() =>
  dutFiles.value.filter(f => {
    const name = f.path.split('/').pop() ?? ''
    const parts = f.path.split('/')
    return parts.length === 2 && (
      name === 'config.json' || name === 'dut_config.json' ||
      name === '.log_signature.txt' || name === 'log_signature.txt'
    )
  })
)

const runtimeLogFiles = computed(() =>
  dutFiles.value.filter(f => {
    const name = f.path.split('/').pop() ?? ''
    const parts = f.path.split('/')
    return parts.length === 2 && (
      name === 'Execution_Summary_Report.txt' ||
      name === 'nvdebug_runtime_output.txt' ||
      name === 'nvdebug_runtime_output_structured.txt' ||
      name.endsWith('_stdout.log')
    )
  })
)

const errorLogFiles = computed(() =>
  dutFiles.value.filter(f => f.path.includes('/error-logs/') || f.path.includes('/error_logs/'))
)

const allPreflightChecks = computed(() => {
  const preflight = manifestStore.manifest?.preflight?.per_dut ?? []
  const dutPreflight = preflight.find((p: any) => p.dut_id === dutId.value)
  return dutPreflight?.checks ?? []
})

function isPreflightPass(s: string) {
  return s === 'pass' || s === 'passed' || s === 'success'
}
function isPreflightFail(s: string) {
  return s === 'fail' || s === 'failed' || s === 'error'
}

const preflightPassCount = computed(() =>
  (allPreflightChecks.value as any[]).filter((c: any) => isPreflightPass(c.status ?? '')).length
)

const allPreflightPassed = computed(() =>
  preflightPassCount.value === (allPreflightChecks.value as any[]).length && (allPreflightChecks.value as any[]).length > 0
)

const preflightFailures = computed(() =>
  (allPreflightChecks.value as any[]).filter((c: any) => isPreflightFail(c.status ?? ''))
)

const SERVICE_ORDER = ['host', 'ipmi', 'redfish', 'ssh']

interface PreflightServiceSummary {
  name: string
  label: string
  status: string
  count: number
  passCount: number
}

const preflightByService = computed((): PreflightServiceSummary[] => {
  const checks = allPreflightChecks.value as any[]
  if (checks.length === 0) return []
  const serviceMap = new Map<string, PreflightServiceSummary>()
  for (const c of checks) {
    const key = (c.group || c.name || '').toLowerCase()
    if (!serviceMap.has(key)) {
      serviceMap.set(key, {
        name: key,
        label: c.name || key,
        status: c.status || 'na',
        count: 0,
        passCount: 0,
      })
    }
    const entry = serviceMap.get(key)!
    entry.count++
    if (isPreflightPass(c.status ?? '')) entry.passCount++
    if (isPreflightFail(c.status ?? '') && !isPreflightFail(entry.status)) {
      entry.status = c.status
    }
  }
  const ordered = SERVICE_ORDER
    .filter(s => serviceMap.has(s))
    .map(s => serviceMap.get(s)!)
  for (const [key, val] of serviceMap) {
    if (!SERVICE_ORDER.includes(key)) ordered.push(val)
  }
  return ordered
})

function preflightChipClass(status: string) {
  if (isPreflightPass(status)) return 'preflight-chip--pass'
  if (isPreflightFail(status)) return 'preflight-chip--fail'
  return 'preflight-chip--na'
}

const fileCategories = computed(() => {
  const files = dutFiles.value.filter(f => {
    const parts = f.path.split('/')
    return parts.length >= 3 && parts[1] !== '.metadata' && parts[1] !== 'metadata'
  })
  const grouped = new Map<string, typeof files>()
  for (const f of files) {
    const category = f.collector_group || f.path.split('/')[1] || 'Other'
    if (!grouped.has(category)) grouped.set(category, [])
    grouped.get(category)!.push(f)
  }
  return Array.from(grouped.entries())
    .map(([name, files]) => ({ name, files }))
    .sort((a, b) => a.name.localeCompare(b.name))
})

function onCollectorClick(row: any) {
  router.push(`/dut/${dutId.value}/${row._group}/${row._collectorId}`)
}


function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i]
}
</script>

<style scoped>
/* --- File type badges --- */
.file-type-badge {
  display: inline-block;
  padding: 1px 4px;
  border-radius: 3px;
  font-size: 0.5625rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  line-height: 1.4;
  flex-shrink: 0;
}
.file-type-badge--json { background: color-mix(in srgb, var(--nv-chart-purple) 15%, transparent); color: var(--nv-chart-purple); }
.file-type-badge--text { background: color-mix(in srgb, var(--nv-chart-blue) 15%, transparent); color: var(--nv-chart-blue); }
.file-type-badge--log { background: var(--nv-success-muted); color: var(--nv-success); }
.file-type-badge--binary { background: color-mix(in srgb, var(--nv-chart-slate) 15%, transparent); color: var(--nv-chart-slate); }
.file-type-badge--xml { background: var(--nv-skipped-muted); color: var(--nv-skipped); }
.file-type-badge--yaml { background: color-mix(in srgb, var(--nv-chart-teal) 15%, transparent); color: var(--nv-chart-teal); }

/* --- File cell in table --- */
.file-cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.file-cell__item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
}
.file-cell__link {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: block;
  max-width: 280px;
}

/* --- Files modal (enhanced) --- */
.files-modal {
  display: flex;
  flex-direction: column;
  gap: 2px;
  max-height: 500px;
  overflow-y: auto;
}
.files-modal__group-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  margin-top: 6px;
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--nv-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  border-bottom: 1px solid var(--nv-glass-border);
}
.files-modal__group-header:first-child { margin-top: 0; }
.files-modal__group-count {
  margin-left: auto;
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  font-weight: 400;
}
.files-modal__item {
  font-size: 0.75rem;
  padding: 5px 8px;
  border-radius: var(--nv-radius-sm);
  display: flex;
  align-items: center;
  gap: 8px;
}
.files-modal__name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.files-modal__badge {
  font-size: 0.5625rem;
  padding: 1px 5px;
  border-radius: 6px;
  font-weight: 600;
  flex-shrink: 0;
}
.files-modal__badge--diag {
  background: color-mix(in srgb, var(--nv-chart-purple) 12%, transparent);
  color: var(--nv-chart-purple);
}
.files-modal__size {
  margin-left: auto;
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
  flex-shrink: 0;
}

/* --- Dependencies chips (compact summary) --- */
.deps-chip-list {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 10px;
}
.deps-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 16px;
  font-size: 0.6875rem;
  border: 1px solid var(--nv-glass-border);
  background: var(--nv-glass-bg-light);
  cursor: pointer;
  color: var(--nv-text-secondary);
  transition: all 0.15s ease;
}
.deps-chip:hover {
  border-color: var(--nv-accent);
  color: var(--nv-accent);
  background: var(--nv-accent-muted);
}
.deps-chip__id { font-weight: 600; font-family: var(--nv-font-mono, monospace); }
.deps-chip__arrow { opacity: 0.4; }
.deps-chip__count { opacity: 0.7; }
.deps-chip--more {
  color: var(--nv-accent);
  border-color: var(--nv-accent);
  font-weight: 600;
}

/* --- Preflight --- */
.preflight-summary {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.preflight-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: var(--nv-radius-md);
  font-size: var(--nv-text-sm);
  font-weight: var(--nv-weight-medium);
  border: 1px solid var(--nv-glass-border);
  transition: all var(--nv-duration-fast) var(--nv-ease);
  cursor: pointer;
  font-family: inherit;
}
.preflight-chip:hover {
  filter: brightness(1.15);
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
}
.preflight-chip:active {
  transform: translateY(0);
}
.preflight-chip--pass {
  background: var(--nv-success-muted);
  border-color: color-mix(in srgb, var(--nv-success) 25%, transparent);
  color: var(--nv-success);
}
.preflight-chip--fail {
  background: var(--nv-error-muted);
  border-color: color-mix(in srgb, var(--nv-error) 25%, transparent);
  color: var(--nv-error);
}
.preflight-chip--na {
  background: var(--nv-bg-tertiary);
  color: var(--nv-text-secondary);
}
.preflight-chip__icon {
  font-size: 0.875rem;
}
.preflight-chip__label {
  text-transform: uppercase;
  font-size: 0.6875rem;
  letter-spacing: 0.04em;
}
.preflight-chip__count {
  font-size: 0.6875rem;
  opacity: 0.7;
}

.preflight-failures-toggle {
  cursor: pointer;
  font-size: var(--nv-text-sm);
  padding: 6px 0;
  background: none;
  border: none;
  font-family: inherit;
  text-align: left;
}
.preflight-failures-toggle:hover {
  text-decoration: underline;
}

.not-ran-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  user-select: none;
}
.not-ran-toggle__input {
  accent-color: var(--nv-accent);
  width: 14px;
  height: 14px;
  cursor: pointer;
}
.not-ran-toggle__label {
  font-size: var(--nv-text-xs);
  color: var(--nv-text-secondary);
  display: flex;
  align-items: center;
  gap: 4px;
}
</style>
