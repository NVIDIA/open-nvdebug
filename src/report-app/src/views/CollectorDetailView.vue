<template>
  <div style="min-height: calc(100vh - 88px);">
    <!-- Left Sidebar (same as DutView) -->
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

      <!-- Collectors in this group -->
      <div v-if="siblingCollectors.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">
          {{ resolvedGroupName }} Collectors
        </h4>
        <router-link
          v-for="c in siblingCollectors"
          :key="c.id"
          :to="`/dut/${dutId}/${resolvedGroupName}/${c.id}`"
          :class="['nv-sidebar__link', { 'nv-sidebar__link--active': c.id.toLowerCase() === collectorId.toLowerCase() }]"
          style="font-size: 0.6875rem; padding: 3px 0; display: flex; align-items: center; gap: 6px;"
        >
          <span :style="{ color: statusDotColor(c.status), fontSize: '8px' }">&#9679;</span>
          <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ c.id }} — {{ c.name }}</span>
          <StatusBadge v-if="c.id.toLowerCase() === collectorId.toLowerCase()" :status="c.status" style="transform: scale(0.8); transform-origin: right center;" />
        </router-link>
      </div>

      <!-- Files from this collector -->
      <div v-if="dedupedFiles.length > 0" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">
          Collected Files <span class="nv-badge nv-badge--neutral" style="margin-left: auto;">{{ dedupedFiles.length }}</span>
        </h4>
        <router-link
          v-for="f in dedupedFiles"
          :key="f.path"
          :to="`/file/${encodeURIComponent(f.path)}`"
          class="nv-sidebar__link"
          style="font-size: 0.6875rem; padding: 2px 0; display: flex; align-items: center; gap: 4px;"
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M1.5 0.5h4l2.5 2.5v6h-6.5v-8.5z" stroke="currentColor" stroke-width="0.5"/></svg>
          <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ fileName(f.path) }}</span>
        </router-link>
      </div>
    </div>

    <!-- Main Content -->
    <div class="nv-page" style="margin-left: 260px;">
      <div v-if="!collector" class="nv-glass" style="padding: 48px 32px; text-align: center; margin-top: 24px; border-radius: var(--nv-radius-lg);">
        <div style="font-size: 2.5rem; margin-bottom: 12px; opacity: 0.25;">&#128269;</div>
        <h3 style="font-size: 1rem; font-weight: 600; color: var(--nv-text-primary); margin: 0 0 8px;">Collector Not Found</h3>
        <p style="font-size: 0.8125rem; color: var(--nv-text-secondary); margin: 0 0 6px; max-width: 440px; margin-inline: auto; line-height: 1.5;">
          Could not find collector <strong>{{ collectorId }}</strong> in group <strong>{{ groupName }}</strong> on node <strong>{{ dutId }}</strong>.
        </p>
        <p style="font-size: 0.75rem; color: var(--nv-text-tertiary); margin: 0 0 20px; max-width: 440px; margin-inline: auto; line-height: 1.5;">
          The collector may not have been executed in this run, or the group name may differ. Check the node's collector groups below.
        </p>
        <div style="display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;">
          <router-link :to="`/dut/${dutId}`" class="nv-btn nv-btn--primary">View Node</router-link>
          <router-link to="/" class="nv-btn">Dashboard</router-link>
        </div>
      </div>
      <template v-else>
        <Breadcrumbs :items="breadcrumbs" />

        <!-- Page Header -->
        <div class="cd-header nv-glass--elevated">
          <div class="cd-header__main">
            <span class="cd-header__id">{{ collector.id }}</span>
            <h2 class="cd-header__name">{{ collector.name }}</h2>
            <StatusBadge :status="collector.status" />
          </div>
          <div class="cd-header__actions">
            <CopyForTicket :text="ticketText" />
          </div>
        </div>

        <!-- Stat Cards Row -->
        <div class="cd-stats">
          <div :class="['nv-stat', `nv-stat--${statusColor}`]">
            <div class="nv-stat__label">Status</div>
            <div class="nv-stat__value">{{ statusLabel }}</div>
          </div>
          <div class="nv-stat nv-stat--blue">
            <div class="nv-stat__label">Execution Time</div>
            <div class="nv-stat__value">{{ formatDuration(collector.execution_time) }}</div>
          </div>
          <div class="nv-stat nv-stat--purple">
            <div class="nv-stat__label">Collection Level</div>
            <div class="nv-stat__value">{{ collector.collection_level || '\u2014' }}</div>
          </div>
          <div class="nv-stat nv-stat--emerald">
            <div class="nv-stat__label">Files Collected</div>
            <div class="nv-stat__value">{{ dedupedFiles.length }}</div>
          </div>
        </div>

        <!-- Reason / Error Banner (non-success only) -->
        <div v-if="collector.reason && collector.status !== 'success' && collector.status !== 'not_ran'" class="cd-reason nv-glass">
          <div style="color: var(--nv-error); flex-shrink: 0; margin-top: 1px;">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <circle cx="10" cy="10" r="9" stroke="currentColor" stroke-width="1.5"/>
              <path d="M10 6v5M10 13.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            </svg>
          </div>
          <div>
            <div style="font-size: 0.8125rem; font-weight: 600; color: var(--nv-error); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em;">Failure Reason</div>
            <ReasonDisplay :text="collector.reason" />
          </div>
        </div>

        <!-- Success result note -->
        <div v-if="collector.reason && collector.status === 'success'" class="cd-info-note nv-glass">
          <div style="color: var(--nv-success); flex-shrink: 0; margin-top: 1px;">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <circle cx="10" cy="10" r="9" stroke="currentColor" stroke-width="1.5"/>
              <path d="M6.5 10.5l2 2 5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div>
            <div style="font-size: 0.8125rem; font-weight: 600; color: var(--nv-success); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em;">Result</div>
            <ReasonDisplay :text="collector.reason" />
          </div>
        </div>

        <!-- Execution Details (2-col grid) -->
        <div class="cd-details-grid">
          <!-- Left: Execution Info -->
          <div class="nv-card">
            <h3 class="cd-section-title">Execution Details</h3>
            <div class="cd-kv-list">
              <div class="cd-kv">
                <span class="cd-kv__label">Collector ID</span>
                <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ collector.id }}</span>
              </div>
              <div class="cd-kv">
                <span class="cd-kv__label">Collector Name</span>
                <span class="cd-kv__value">{{ collector.name }}</span>
              </div>
              <div class="cd-kv">
                <span class="cd-kv__label">Service Group</span>
                <span class="cd-kv__value"><ServiceBadge :service="groupName" /></span>
              </div>
              <div class="cd-kv">
                <span class="cd-kv__label">Status</span>
                <span class="cd-kv__value"><StatusBadge :status="collector.status" /></span>
              </div>
              <div class="cd-kv">
                <span class="cd-kv__label">Collection Level</span>
                <span class="cd-kv__value">{{ collector.collection_level || '\u2014' }}</span>
              </div>
              <div v-if="collectorPriority != null" class="cd-kv">
                <span class="cd-kv__label">Priority</span>
                <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ collectorPriority }}</span>
              </div>
              <div class="cd-kv">
                <span class="cd-kv__label">Execution Time</span>
                <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatDuration(collector.execution_time) }}</span>
              </div>
              <div v-if="collector.start_time" class="cd-kv">
                <span class="cd-kv__label">Start Time</span>
                <span class="cd-kv__value" style="font-family: var(--nv-font-mono); font-size: 0.75rem;">{{ collector.start_time }}</span>
              </div>
              <div v-if="collector.end_time" class="cd-kv">
                <span class="cd-kv__label">End Time</span>
                <span class="cd-kv__value" style="font-family: var(--nv-font-mono); font-size: 0.75rem;">{{ collector.end_time }}</span>
              </div>
              <div v-if="collectorCommand" class="cd-kv">
                <span class="cd-kv__label">{{ collectorCommandLabel }}</span>
                <span class="cd-kv__value cd-kv__value--mono-wrap">{{ collectorCommand }}</span>
              </div>
              <div class="cd-kv">
                <span class="cd-kv__label">Total Log Size</span>
                <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatBytes(totalLogSize) }}</span>
              </div>
            </div>
          </div>

          <!-- Right: Stage Timing -->
          <div class="nv-card">
            <h3 class="cd-section-title">Stage Timing</h3>
            <template v-if="hasStageData">
              <div class="cd-stage-bar">
                <div
                  v-for="seg in stageSegments"
                  :key="seg.stage"
                  class="cd-stage-bar__segment"
                  :style="{ flex: seg.flex, background: seg.color }"
                  :title="`${seg.label}: ${seg.value.toFixed(2)}s (${seg.pct}%)`"
                >
                  <span v-if="seg.flex > 0.08" class="cd-stage-bar__label">{{ seg.value.toFixed(1) }}s</span>
                </div>
              </div>
              <div class="cd-stage-legend">
                <div v-for="seg in stageSegments" :key="seg.stage" class="cd-stage-legend__item">
                  <span class="cd-stage-legend__swatch" :style="{ background: seg.color }"></span>
                  <span style="color: var(--nv-text-secondary);">{{ seg.label }}</span>
                  <span style="font-weight: 600; font-family: var(--nv-font-mono); color: var(--nv-text-primary);">{{ seg.value.toFixed(2) }}s</span>
                  <span style="color: var(--nv-text-tertiary); font-size: 0.6875rem;">({{ seg.pct }}%)</span>
                </div>
              </div>
            </template>
            <div v-else style="color: var(--nv-text-tertiary); font-size: 0.8125rem; padding: 12px 0;">
              No stage timing data available for this collector.
            </div>
          </div>
        </div>

        <!-- Execution Summary (if there's any) -->
        <div v-if="executionSummary && Object.keys(executionSummary).length > 0" class="nv-card" style="margin-bottom: 16px;">
          <h3 class="cd-section-title">Execution Summary</h3>
          <div class="cd-kv-list">
            <div v-for="(val, key) in executionSummary" :key="key" class="cd-kv">
              <span class="cd-kv__label">{{ String(key) }}</span>
              <span class="cd-kv__value" style="font-family: var(--nv-font-mono); word-break: break-all;">{{ formatSummaryValue(val) }}</span>
            </div>
          </div>
        </div>

        <!-- Error Details (prominent glass panel) -->
        <div v-if="errorDetails.length > 0" class="cd-error-panel nv-glass--elevated" style="margin-bottom: 16px;">
          <div class="cd-error-panel__header">
            <h3 class="cd-section-title" style="margin-bottom: 0;">
              <svg width="18" height="18" viewBox="0 0 20 20" fill="none" style="vertical-align: -3px; margin-right: 4px;">
                <circle cx="10" cy="10" r="9" stroke="currentColor" stroke-width="1.5"/>
                <path d="M10 6v5M10 13.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              </svg>
              Error Details
              <span class="cd-count-badge cd-count-badge--error">{{ errorDetails.length }}</span>
            </h3>
            <CopyButton :text="errorClipboardText" />
          </div>
          <div class="cd-error-panel__body">
            <div v-for="(err, i) in errorDetails" :key="i" class="cd-error-item">
              <div class="cd-error-item__stage" v-if="errorStage(err)">{{ errorStage(err) }}</div>
              <div class="cd-error-item__message"><ReasonDisplay :text="errorMessage(err)" :compact="true" /></div>
            </div>
          </div>
        </div>

        <!-- Dependencies -->
        <div v-if="collector.dependencies.length > 0 || reverseDeps.length > 0" class="cd-details-grid" style="margin-bottom: 16px;">
          <div v-if="collector.dependencies.length > 0" class="nv-card">
            <h3 class="cd-section-title">
              Depends On
              <span class="cd-count-badge">{{ collector.dependencies.length }}</span>
            </h3>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
              <router-link
                v-for="dep in collector.dependencies"
                :key="depId(dep)"
                :to="depRoute(depId(dep))"
                class="cd-dep-badge"
              >{{ depId(dep) }}</router-link>
            </div>
          </div>

          <div v-if="reverseDeps.length > 0" class="nv-card">
            <h3 class="cd-section-title">
              Depended By
              <span class="cd-count-badge">{{ reverseDeps.length }}</span>
            </h3>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
              <router-link
                v-for="dep in reverseDeps"
                :key="dep.collector_id"
                :to="depRoute(dep.collector_id)"
                class="cd-dep-badge cd-dep-badge--reverse"
              >
                {{ dep.collector_id }}
                <span v-if="dep.name" class="cd-dep-badge__name">{{ dep.name }}</span>
              </router-link>
            </div>
          </div>
        </div>

        <!-- Files Table (DataTable) -->
        <div v-if="dedupedFiles.length > 0" class="nv-card" style="margin-bottom: 16px;">
          <h3 class="cd-section-title">
            Collected Files
            <span class="cd-count-badge">{{ dedupedFiles.length }}</span>
          </h3>
          <DataTable
            :columns="fileColumns"
            :data="fileTableData"
            :searchable="dedupedFiles.length > 5"
            :page-size="0"
            @row-click="onFileRowClick"
          >
            <template #cell-name="{ row }">
              <span style="font-weight: 500;">{{ row.name }}</span>
            </template>
            <template #cell-size="{ value }">
              <span style="font-family: var(--nv-font-mono); font-size: 0.75rem; white-space: nowrap;">{{ formatBytes(value) }}</span>
            </template>
            <template #cell-type="{ value }">
              <span :class="['nv-badge', typeBadgeClass(value)]">{{ value }}</span>
            </template>
          </DataTable>
        </div>

        <!-- Empty state: not_ran -->
        <div v-if="collector.status === 'not_ran'" class="nv-glass--subtle" style="padding: 32px; text-align: center; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <div style="font-size: 2rem; margin-bottom: 8px; opacity: 0.3;">&#9940;</div>
          <div style="font-size: 0.875rem; font-weight: 600; color: var(--nv-text-primary);">This collector was not executed</div>
          <div style="font-size: 0.75rem; color: var(--nv-text-tertiary); margin-top: 6px; max-width: 420px; margin-inline: auto; line-height: 1.5;">
            Possible reasons: not applicable to this baseboard, excluded by collection level, or not selected for this run.
          </div>
        </div>

        <!-- Empty state: skipped -->
        <div v-else-if="collector.status === 'skipped' && dedupedFiles.length === 0" class="nv-glass--subtle" style="padding: 32px; text-align: center; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <div style="font-size: 2rem; margin-bottom: 8px; opacity: 0.3;">&#9193;</div>
          <div style="font-size: 0.875rem; font-weight: 600; color: var(--nv-text-primary);">This collector was skipped</div>
          <div v-if="collector.reason" style="margin-top: 6px;">
            <ReasonDisplay :text="collector.reason" :compact="true" />
          </div>
        </div>

        <!-- Empty state: other statuses with no files -->
        <div v-else-if="dedupedFiles.length === 0" class="nv-glass--subtle" style="padding: 32px; text-align: center; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <div style="font-size: 2rem; margin-bottom: 8px; opacity: 0.3;">&#128196;</div>
          <div style="font-size: 0.875rem; color: var(--nv-text-secondary);">This collector did not produce any output files.</div>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { formatCollectorForTicket } from '@/composables/useCopyForTicket'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import CopyForTicket from '@/components/common/CopyForTicket.vue'
import CopyButton from '@/components/common/CopyButton.vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import DataTable from '@/components/common/DataTable.vue'
import { dedupFiles } from '@/utils/dedupFiles'
import { formatDuration } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const manifestStore = useManifestStore()

const dutId = computed(() => String(route.params.dutId))
const groupName = computed(() => String(route.params.group))
const collectorId = computed(() => String(route.params.collectorId))

const dut = computed(() => manifestStore.dutById(dutId.value))

function findGroup(d: typeof dut.value) {
  if (!d) return undefined
  const gn = groupName.value.toLowerCase()
  return d.collector_groups.find(g => g.name.toLowerCase() === gn)
}

const resolvedGroup = computed(() => findGroup(dut.value))
const resolvedGroupName = computed(() => resolvedGroup.value?.name ?? groupName.value)

function findCollectorById(cid: string, groups: typeof dut.value extends undefined ? never : NonNullable<typeof dut.value>['collector_groups']) {
  const cidLower = cid.toLowerCase()
  for (const g of groups) {
    const c = g.collectors.find(c => c.id.toLowerCase() === cidLower)
    if (c) return c
  }
  return undefined
}

const collector = computed(() => {
  const cid = collectorId.value.toLowerCase()
  const fromGroup = resolvedGroup.value?.collectors.find(c => c.id.toLowerCase() === cid)
  if (fromGroup) return fromGroup
  const d = dut.value
  if (!d) return undefined
  return findCollectorById(collectorId.value, d.collector_groups)
})

const allSiblingCollectors = computed(() => {
  if (resolvedGroup.value) return resolvedGroup.value.collectors
  const d = dut.value
  if (!d || !collector.value) return []
  const cid = collectorId.value.toLowerCase()
  for (const g of d.collector_groups) {
    if (g.collectors.some(c => c.id.toLowerCase() === cid)) return g.collectors
  }
  return []
})

const siblingCollectors = computed(() =>
  allSiblingCollectors.value.filter(c => c.status !== 'not_ran' || c.id === collectorId.value)
)

const breadcrumbs = computed(() => [
  { label: 'Home', to: '/' },
  { label: dutId.value, to: '/dut/' + dutId.value },
  { label: resolvedGroupName.value, to: '/dut/' + dutId.value + '/' + resolvedGroupName.value },
  { label: (collector.value?.id ?? '') + ' \u2014 ' + (collector.value?.name ?? '') },
])

const ticketText = computed(() => {
  if (!collector.value || !dut.value) return ''
  return formatCollectorForTicket(dut.value, groupName.value, collector.value)
})

const dedupedFiles = computed(() =>
  dedupFiles(collector.value?.files ?? [])
)

const totalLogSize = computed(() =>
  dedupedFiles.value.reduce((sum, f) => sum + (f.size || 0), 0)
)

const executionSummary = computed(() =>
  (collector.value as any)?.execution_summary ?? null
)

const errorDetails = computed((): any[] =>
  (collector.value as any)?.error_details ?? []
)

// --- Priority & Command/URI ---
const collectorPriority = computed(() => (collector.value as any)?.priority ?? null)

const collectorCommand = computed(() => {
  const c = collector.value as any
  return c?.command ?? c?.uri ?? c?.endpoint ?? c?.cmd ?? null
})

const collectorCommandLabel = computed(() => {
  const c = collector.value as any
  if (c?.uri || c?.endpoint) return 'URI'
  if (c?.command || c?.cmd) return 'Command'
  return 'Command/URI'
})

// --- Reverse Dependencies ---
const reverseDeps = computed(() => {
  const depCheck = manifestStore.manifest?.dependency_check?.per_dut ?? []
  const dutDeps = depCheck.find(d => d.dut_id === dutId.value)
  if (!dutDeps) return []
  const cidLower = collectorId.value.toLowerCase()
  return dutDeps.collectors.filter(
    c => c.collector_id.toLowerCase() !== cidLower && c.dependencies.some(
      d => (typeof d === 'object' && d !== null ? String((d as any).name) : String(d)).toLowerCase() === cidLower
    )
  )
})

// --- Error helpers ---
function errorMessage(err: any): string {
  if (typeof err === 'string') return err
  if (err?.message) return err.message
  try { return JSON.stringify(err) } catch { return String(err) }
}

function errorStage(err: any): string | null {
  if (typeof err === 'object' && err !== null && err.stage) return err.stage
  return null
}

const errorClipboardText = computed(() => {
  if (!collector.value) return ''
  const lines = [`Collector: ${collector.value.id} — ${collector.value.name}`]
  if (collector.value.reason) lines.push(`Reason: ${collector.value.reason}`)
  for (const err of errorDetails.value) {
    const stage = errorStage(err)
    lines.push(stage ? `[${stage}] ${errorMessage(err)}` : errorMessage(err))
  }
  return lines.join('\n')
})

// --- Status helpers ---
const STATUS_COLORS: Record<string, string> = {
  success: 'green', error: 'red', partial: 'amber', skipped: 'slate', not_ran: 'slate',
}
const STATUS_LABELS: Record<string, string> = {
  success: 'Success', error: 'Error', partial: 'Partial', skipped: 'Skipped', not_ran: 'Not Ran',
}

const statusColor = computed(() => STATUS_COLORS[collector.value?.status ?? ''] ?? 'slate')
const statusLabel = computed(() => STATUS_LABELS[collector.value?.status ?? ''] ?? collector.value?.status ?? 'Unknown')

function statusDotColor(status: string): string {
  const map: Record<string, string> = {
    success: 'var(--nv-success)', error: 'var(--nv-error)', partial: 'var(--nv-warning)',
    skipped: 'var(--nv-skipped)', not_ran: 'var(--nv-text-tertiary)',
  }
  return map[status] ?? 'var(--nv-text-tertiary)'
}

// --- Stage Timing (CSS flexbox) ---
const hasStageData = computed(() =>
  collector.value && Object.values(collector.value.stage_timing).some(v => v != null)
)

const STAGE_META: Record<string, { color: string; label: string }> = {
  validation: { color: 'rgba(59,130,246,0.85)', label: 'Validation' },
  discovery: { color: 'rgba(124,58,237,0.85)', label: 'Discovery' },
  execution: { color: 'rgba(118,185,0,0.85)', label: 'Execution' },
  post_processing: { color: 'rgba(217,119,6,0.85)', label: 'Post-Processing' },
}

const stageSegments = computed(() => {
  if (!collector.value) return []
  const timing = collector.value.stage_timing
  const entries = Object.entries(timing).filter(([, v]) => v != null) as [string, number][]
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1
  return entries.map(([stage, val]) => ({
    stage,
    value: val,
    flex: val / total,
    pct: ((val / total) * 100).toFixed(0),
    color: STAGE_META[stage]?.color ?? 'rgba(100,116,139,0.85)',
    label: STAGE_META[stage]?.label ?? stage,
  }))
})

// --- Files DataTable ---
interface FileColumn { key: string; label: string; sortable?: boolean }

const fileColumns: FileColumn[] = [
  { key: 'name', label: 'File Name', sortable: true },
  { key: 'size', label: 'Size', sortable: true },
  { key: 'type', label: 'Type', sortable: true },
]

const fileTableData = computed(() =>
  dedupedFiles.value.map(f => ({
    name: fileName(f.path),
    size: f.size || 0,
    type: f.type,
    _path: f.path,
  }))
)

function onFileRowClick(row: Record<string, any>) {
  router.push(`/file/${encodeURIComponent(row._path)}`)
}

// --- Dependencies helpers ---
function depId(dep: any): string {
  if (typeof dep === 'string') return dep
  return dep?.name ?? dep?.collector_id ?? dep?.id ?? String(dep)
}

function formatSummaryValue(val: unknown): string {
  if (val == null) return '\u2014'
  if (typeof val === 'object') {
    try { return JSON.stringify(val) } catch { return String(val) }
  }
  return String(val)
}

function depRoute(depId: string): string {
  const d = dut.value
  if (!d) return '#'
  for (const g of d.collector_groups) {
    if (g.collectors.some(c => c.id === depId)) {
      return `/dut/${dutId.value}/${g.name}/${depId}`
    }
  }
  return '#'
}

// --- Utilities ---
function fileName(path: string): string {
  return path.split('/').pop() ?? path
}

function typeBadgeClass(type: string): string {
  const map: Record<string, string> = {
    json: 'nv-badge--info', text: 'nv-badge--neutral', log: 'nv-badge--neutral',
    xml: 'nv-badge--info', yaml: 'nv-badge--info', binary: 'nv-badge--warning',
  }
  return map[type] ?? 'nv-badge--neutral'
}

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}

</script>

<style scoped>
/* ── Header ── */
.cd-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 16px 20px;
  margin: 12px 0 16px;
  border-radius: var(--nv-radius-xl);
}
.cd-header__main {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}
.cd-header__id {
  font-family: var(--nv-font-mono);
  font-size: 0.8125rem;
  color: var(--nv-accent);
  background: var(--nv-glass-bg-light);
  padding: 2px 10px;
  border-radius: var(--nv-radius-md);
  border: 1px solid var(--nv-glass-border);
  white-space: nowrap;
}
.cd-header__name {
  font-size: 1.125rem;
  font-weight: 600;
  color: var(--nv-text-primary);
  margin: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.cd-header__actions { flex-shrink: 0; }

/* ── Stats ── */
.cd-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 16px;
}
@media (max-width: 720px) {
  .cd-stats { grid-template-columns: repeat(2, 1fr); }
}

/* ── Reason Banner ── */
.cd-reason {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 14px 18px;
  margin-bottom: 16px;
  border-radius: var(--nv-radius-lg);
  border: 1px solid color-mix(in srgb, var(--nv-error) 35%, transparent);
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--nv-error) 6%, transparent) 0%,
    color-mix(in srgb, var(--nv-error) 3%, transparent) 100%
  );
}

/* ── Info Note (success result) ── */
.cd-info-note {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 14px 18px;
  margin-bottom: 16px;
  border-radius: var(--nv-radius-lg);
  border: 1px solid color-mix(in srgb, var(--nv-success) 30%, transparent);
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--nv-success) 5%, transparent) 0%,
    color-mix(in srgb, var(--nv-success) 2%, transparent) 100%
  );
}

/* ── Details Grid ── */
.cd-details-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 16px;
}
@media (max-width: 800px) {
  .cd-details-grid { grid-template-columns: 1fr; }
}

/* ── Section Titles ── */
.cd-section-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--nv-text-primary);
  margin: 0 0 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.cd-count-badge {
  font-size: 0.6875rem;
  font-weight: 500;
  color: var(--nv-text-secondary);
  background: var(--nv-glass-bg-light);
  border: 1px solid var(--nv-glass-border);
  border-radius: 10px;
  padding: 1px 8px;
}
.cd-count-badge--error {
  color: var(--nv-error);
  border-color: color-mix(in srgb, var(--nv-error) 30%, transparent);
  background: var(--nv-error-muted);
}

/* ── Key-Value List ── */
.cd-kv-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.cd-kv {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 4px 0;
  border-bottom: 1px solid var(--nv-glass-border);
}
.cd-kv:last-child { border-bottom: none; }
.cd-kv__label {
  font-size: 0.75rem;
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
}
.cd-kv__value {
  font-size: 0.8125rem;
  color: var(--nv-text-primary);
  text-align: right;
}
.cd-kv__value--mono-wrap {
  font-family: var(--nv-font-mono);
  font-size: 0.6875rem;
  word-break: break-all;
  max-width: 280px;
  text-align: right;
}

/* ── Stage Timing (CSS flexbox bar) ── */
.cd-stage-bar {
  display: flex;
  height: 28px;
  border-radius: var(--nv-radius-md);
  overflow: hidden;
  border: 1px solid var(--nv-glass-border);
  margin-bottom: 12px;
}
.cd-stage-bar__segment {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 2px;
  transition: flex var(--nv-duration-base) var(--nv-ease);
  position: relative;
}
.cd-stage-bar__label {
  font-size: 0.625rem;
  font-weight: 600;
  color: var(--nv-text-strong);
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
  white-space: nowrap;
  pointer-events: none;
}
.cd-stage-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}
.cd-stage-legend__item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.75rem;
}
.cd-stage-legend__swatch {
  width: 10px;
  height: 10px;
  border-radius: 2px;
  flex-shrink: 0;
}

/* ── Error Panel ── */
.cd-error-panel {
  border-radius: var(--nv-radius-lg);
  border: 1px solid color-mix(in srgb, var(--nv-error) 35%, transparent);
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--nv-error) 5%, transparent) 0%,
    color-mix(in srgb, var(--nv-error) 2%, transparent) 100%
  );
  padding: 16px 20px;
}
.cd-error-panel__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
.cd-error-panel__header .cd-section-title {
  color: var(--nv-error);
}
.cd-error-panel__body {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 300px;
  overflow-y: auto;
}
.cd-error-item {
  padding: 10px 14px;
  border-radius: var(--nv-radius-md);
  background: color-mix(in srgb, var(--nv-error) 6%, transparent);
  border: 1px solid var(--nv-error-muted);
}
.cd-error-item__stage {
  font-size: 0.625rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--nv-error);
  margin-bottom: 4px;
  opacity: 0.8;
}
.cd-error-item__message {
  font-size: 0.75rem;
  color: var(--nv-text-primary);
  line-height: 1.5;
  word-break: break-word;
  font-family: var(--nv-font-mono);
}

/* ── Dependency Badges ── */
.cd-dep-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.75rem;
  font-family: var(--nv-font-mono);
  color: var(--nv-accent);
  background: var(--nv-glass-bg-light);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  padding: 4px 12px;
  text-decoration: none;
  transition: all var(--nv-duration-base) var(--nv-ease);
}
.cd-dep-badge:hover {
  border-color: var(--nv-glass-border-highlight);
  background: var(--nv-glass-bg);
  box-shadow: var(--nv-shadow-sm);
}
.cd-dep-badge--reverse {
  border-color: color-mix(in srgb, var(--nv-chart-purple) 25%, transparent);
  background: color-mix(in srgb, var(--nv-chart-purple) 6%, transparent);
  color: var(--nv-chart-purple);
}
.cd-dep-badge--reverse:hover {
  border-color: color-mix(in srgb, var(--nv-chart-purple) 45%, transparent);
  background: color-mix(in srgb, var(--nv-chart-purple) 12%, transparent);
}
.cd-dep-badge__name {
  font-family: var(--nv-font-family);
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
}
</style>
