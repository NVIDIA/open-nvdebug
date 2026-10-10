<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

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
          <router-link :to="collectorGroupRoute(dutId, group.name)" class="nv-sidebar__link">
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
          :to="collectorDetailRoute(dutId, resolvedGroupName, c.id)"
          :class="['nv-sidebar__link', { 'nv-sidebar__link--active': c.id.toLowerCase() === collectorId.toLowerCase() }]"
          style="font-size: 0.6875rem; padding: 3px 0; display: flex; align-items: center; gap: 6px;"
        >
          <span :style="{ color: statusDotColor(c.status), fontSize: '8px' }">&#9679;</span>
          <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ c.id }} — {{ c.name }}</span>
          <StatusBadge v-if="c.id.toLowerCase() === collectorId.toLowerCase()" :status="c.status" style="transform: scale(0.8); transform-origin: right center;" />
        </router-link>
      </div>

      <!-- Artifact and diagnostic files from this collector -->
      <div
        v-for="section in fileSections"
        :key="`sidebar-${section.key}`"
        class="nv-sidebar__section"
      >
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">
          {{ section.title }} <span class="nv-badge nv-badge--neutral" style="margin-left: auto;">{{ section.files.length }}</span>
        </h4>
        <router-link
          v-for="f in section.files"
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
    <div class="nv-page cd-page">
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
          <router-link :to="dutRoute(dutId)" class="nv-btn nv-btn--primary">View Node</router-link>
          <router-link to="/" class="nv-btn">Dashboard</router-link>
        </div>
      </div>
      <div v-else :key="`${dutId}:${collectorId}`">
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

        <div class="cd-overview nv-card">
          <dl class="cd-summary">
            <div><dt>Duration</dt><dd>{{ formatDuration(collector.execution_time) }}</dd></div>
            <div><dt>Artifacts</dt><dd>{{ partitionedFiles.artifacts.length }}</dd></div>
            <div><dt>Diagnostics</dt><dd>{{ partitionedFiles.diagnostics.length }}</dd></div>
            <div><dt>Total Size</dt><dd>{{ formatBytes(totalLogSize) }}</dd></div>
          </dl>
          <h3 class="cd-stage-title">Stage Timing</h3>
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
            <template v-if="timingLoading">Loading stage timing…</template>
            <template v-else-if="timingError">Stage timing could not be loaded. See the detailed timing message below.</template>
            <template v-else-if="['skipped', 'not_ran', 'cancelled', 'pending'].includes(collector.status)">
              No stage measurements were recorded. Collector status: {{ collector.status }}.
              {{ collector.reason }}
            </template>
            <template v-else>No stage measurements were recorded in this report.</template>
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
            <div style="font-size: 0.8125rem; font-weight: 600; color: var(--nv-error); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.04em;">
              Failure Reason
              <span
                v-if="failureCategoryLabel"
                data-testid="failure-category"
                class="nv-badge nv-badge--neutral"
                style="margin-left: 8px; text-transform: none; letter-spacing: normal;"
              >{{ failureCategoryLabel }}</span>
            </div>
            <ReasonDisplay :text="collector.reason" />
          </div>
        </div>

        <nav class="cd-section-nav" aria-label="Collector sections">
          <button type="button" class="nv-btn nv-btn--ghost nv-btn--sm" @click="jumpToSection(artifactsSection)">Artifacts</button>
          <button type="button" class="nv-btn nv-btn--ghost nv-btn--sm" @click="jumpToSection(runtimeLogsSection)">Runtime Logs</button>
          <button type="button" class="nv-btn nv-btn--ghost nv-btn--sm" @click="jumpToSection(timingSection)">Timing</button>
        </nav>

        <section ref="artifactsSection" class="nv-card cd-anchor" tabindex="-1" aria-labelledby="collector-artifacts-title">
          <h3 id="collector-artifacts-title" class="cd-section-title">
            Collected Artifacts <span class="cd-count-badge">{{ partitionedFiles.artifacts.length }}</span>
          </h3>
          <div v-if="collector.reason && collector.status === 'success'" class="cd-result">
            <ReasonDisplay :text="collector.reason" :compact="true" />
          </div>
          <CollectorFileTable
            v-if="partitionedFiles.artifacts.length"
            :files="partitionedFiles.artifacts"
            state-key="collector-artifacts"
            @show-operation-timing="jumpToSection(timingSection)"
          />
          <div v-else class="cd-empty">
            <p v-if="collector.status === 'not_ran'">This collector was not executed.</p>
            <p v-else-if="collector.status === 'skipped'">This collector was skipped.</p>
            <p v-else>This collector did not produce any collected artifacts.</p>
            <ReasonDisplay v-if="collector.reason && ['not_ran', 'skipped'].includes(collector.status)" :text="collector.reason" :compact="true" />
            <p v-if="partitionedFiles.diagnostics.length">{{ partitionedFiles.diagnostics.length }} diagnostic {{ partitionedFiles.diagnostics.length === 1 ? 'file is' : 'files are' }} available below the runtime logs.</p>
          </div>
        </section>

        <div ref="runtimeLogsSection" class="cd-anchor" tabindex="-1" aria-label="Collector runtime logs">
          <CollectorRuntimeLogs :dut-id="dutId" :collector-id="collector.id" />
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

        <details v-if="partitionedFiles.diagnostics.length" class="nv-card cd-disclosure">
          <summary>Diagnostics <span class="cd-count-badge">{{ partitionedFiles.diagnostics.length }}</span></summary>
          <p class="cd-help">Request, response, task-polling, and command-execution metadata.</p>
          <CollectorFileTable :files="partitionedFiles.diagnostics" state-key="collector-diagnostics" @show-operation-timing="jumpToSection(timingSection)" />
        </details>

        <section ref="timingSection" class="nv-card cd-anchor" tabindex="-1" aria-labelledby="collector-operation-timing-title">
          <h3 id="collector-operation-timing-title" class="cd-section-title">Operation Timing <span v-if="granularTiming" class="cd-count-badge">{{ timedOperations.length }}</span></h3>
          <template v-if="!granularTiming">
            <p v-if="timingLoading" class="cd-help">Loading bounded detailed timing&hellip;</p>
            <div v-else-if="timingError" role="alert" class="cd-info-note">
              <span>{{ timingError }}</span>
              <button class="nv-btn" type="button" @click="loadDetailedTiming">Retry</button>
            </div>
            <p v-else class="cd-help">No operation measurements were recorded in this report.</p>
          </template>
          <template v-else>
            <p style="margin: -4px 0 12px; color: var(--nv-text-tertiary); font-size: 0.75rem; line-height: 1.5;">
              Collector wall time is authoritative. Cumulative work sums only top-level operations; nested detail is excluded to avoid double-counting. Parallel work can make cumulative time exceed wall time, while active time is the union of measured operations.
            </p>
            <div class="cd-details-grid" style="margin-bottom: 12px;">
              <div class="cd-kv-list">
                <div class="cd-kv">
                  <span class="cd-kv__label">Collector Wall Time</span>
                  <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatDuration(granularTiming.wall_clock_duration_seconds) }}</span>
                </div>
                <div class="cd-kv">
                  <span class="cd-kv__label">Active Measured Time</span>
                  <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatDuration(granularTiming.active_operation_union_seconds) }}</span>
                </div>
              </div>
              <div class="cd-kv-list">
                <div class="cd-kv">
                  <span class="cd-kv__label">Cumulative Work Time</span>
                  <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatDuration(granularTiming.cumulative_operation_time_seconds) }}</span>
                </div>
                <div class="cd-kv">
                  <span class="cd-kv__label">Nested Detail Excluded</span>
                  <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatDuration(granularTiming.nested_operation_time_excluded_seconds) }}</span>
                </div>
                <div class="cd-kv">
                  <span class="cd-kv__label">Unattributed Wall Time</span>
                  <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ formatDuration(granularTiming.unattributed_wall_time_seconds) }}</span>
                </div>
              </div>
            </div>
            <DataTable
              v-if="operationTableData.length > 0"
              class="cd-operation-table"
              :columns="operationColumns"
              :data="operationTableData"
              :searchable="operationTableData.length > 5"
              :page-size="25"
              state-key="collector-operation-timing"
            >
              <template #cell-duration_seconds="{ value, row }">
                <span style="font-family: var(--nv-font-mono); font-size: 0.75rem; white-space: nowrap;">{{ formatArtifactDuration(value, row) }}</span>
              </template>
              <template #cell-status="{ value }">
                <span :class="['nv-badge', operationStatusBadgeClass(value)]">{{ value }}</span>
              </template>
            </DataTable>
          </template>
        </section>

        <details class="nv-card cd-disclosure">
          <summary>Execution Details</summary>
          <p class="cd-help">Collection status reflects nvdebug execution and artifact capture. Health or diagnostic verdicts embedded inside a captured artifact remain part of that artifact's content.</p>
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
            <div v-if="failureCategoryLabel" class="cd-kv">
              <span class="cd-kv__label">Failure Category</span>
              <span class="cd-kv__value" style="font-family: var(--nv-font-mono);">{{ failureCategoryLabel }}</span>
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
        </details>

        <details v-if="collector.dependencies.length > 0 || reverseDeps.length > 0" class="nv-card cd-disclosure">
          <summary>Dependencies</summary>
          <div class="cd-details-grid">
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
        </details>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { formatCollectorForTicket } from '@/composables/useCopyForTicket'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import CopyForTicket from '@/components/common/CopyForTicket.vue'
import CopyButton from '@/components/common/CopyButton.vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import DataTable from '@/components/common/DataTable.vue'
import CollectorRuntimeLogs from '@/components/collector/CollectorRuntimeLogs.vue'
import CollectorFileTable from '@/components/collector/CollectorFileTable.vue'
import { dedupFiles as deduplicateFiles, partitionCollectorFiles } from '@/utils/dedupFiles'
import { formatDuration } from '@/utils/format'
import { resolveStageTiming, selectPreferredArtifactTimings, stageTimingFromOperations } from '@/utils/timing'
import type { GranularCollectorTiming } from '@/types/manifest'
import type { RouteLocationRaw } from 'vue-router'
import { collectorDetailRoute, collectorGroupRoute, dutRoute } from '@/utils/reportRoutes'

const route = useRoute()
const manifestStore = useManifestStore()
const artifactsSection = ref<HTMLElement | null>(null)
const runtimeLogsSection = ref<HTMLElement | null>(null)
const timingSection = ref<HTMLElement | null>(null)

function jumpToSection(section: HTMLElement | null) {
  if (!section) return
  section.focus({ preventScroll: true })
  section.scrollIntoView({ block: 'start' })
}

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

const failureCategoryLabel = computed(() =>
  collector.value?.failure_category?.replace(/-/g, ' ') ?? '',
)

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
  { label: dutId.value, to: dutRoute(dutId.value) },
  { label: resolvedGroupName.value, to: collectorGroupRoute(dutId.value, resolvedGroupName.value) },
  { label: (collector.value?.id ?? '') + ' \u2014 ' + (collector.value?.name ?? '') },
])

const ticketText = computed(() => {
  if (!collector.value || !dut.value) return ''
  return formatCollectorForTicket(dut.value, groupName.value, collector.value)
})

const loadedGranularTiming = ref<GranularCollectorTiming | null>(null)
const loadedTimingKey = ref('')
const granularTiming = computed(
  () => loadedGranularTiming.value ?? collector.value?.timing ?? null,
)
const timingArtifacts = computed(() => selectPreferredArtifactTimings(
  granularTiming.value?.artifact_timings ?? [],
))
const dedupedFiles = computed(() =>
  deduplicateFiles(collector.value?.files ?? []).map(file => {
    const artifact = timingArtifacts.value.get(file.path)
    if (!artifact) return file
    return {
      ...file,
      produced_by_operation_id: artifact.operation_id,
      measurement: artifact.measurement,
      measurement_quality: artifact.measurement_quality,
      measurement_scope: artifact.measurement_scope,
      shared_operation_artifact_count: artifact.shared_operation_artifact_count,
      shared_request_operation_count: artifact.shared_request_operation_count,
      started_at: artifact.started_at,
      ended_at: artifact.ended_at,
      duration_seconds: artifact.duration_seconds,
      status: artifact.status,
    }
  })
)

const partitionedFiles = computed(() => partitionCollectorFiles(dedupedFiles.value))

const totalLogSize = computed(() =>
  dedupedFiles.value.reduce((sum, f) => sum + (f.size || 0), 0)
)

const executionSummary = computed(() =>
  (collector.value as any)?.execution_summary ?? null
)

const errorDetails = computed((): any[] =>
  (collector.value as any)?.error_details ?? []
)

const timingLoading = ref(false)
const timingError = ref('')

async function loadDetailedTiming() {
  const currentCollector = collector.value
  const reference = currentCollector?.timing_ref
  if (!currentCollector || !reference || currentCollector.timing) return
  const requestKey = `${dutId.value}:${currentCollector.id}:${reference.sha256}`
  if (loadedTimingKey.value === requestKey && loadedGranularTiming.value) return
  timingLoading.value = true
  timingError.value = ''
  try {
    const timing = await manifestStore.loadCollectorTiming(
      dutId.value,
      currentCollector.id,
      reference,
    )
    if (
      `${dutId.value}:${collector.value?.id ?? ''}:${collector.value?.timing_ref?.sha256 ?? ''}`
      === requestKey
    ) {
      loadedGranularTiming.value = timing
      loadedTimingKey.value = requestKey
    }
  } catch (error) {
    if (
      `${dutId.value}:${collector.value?.id ?? ''}:${collector.value?.timing_ref?.sha256 ?? ''}`
      === requestKey
    ) {
      timingError.value = String(error instanceof Error ? error.message : error)
    }
  } finally {
    if (
      `${dutId.value}:${collector.value?.id ?? ''}:${collector.value?.timing_ref?.sha256 ?? ''}`
      === requestKey
    ) {
      timingLoading.value = false
    }
  }
}

watch(
  () => [
    dutId.value,
    collector.value?.id,
    collector.value?.timing_ref?.source,
    collector.value?.timing_ref?.size_bytes,
    collector.value?.timing_ref?.sha256,
    collector.value?.timing_ref?.snapshot_generation,
  ],
  () => {
    loadedGranularTiming.value = null
    loadedTimingKey.value = ''
    timingLoading.value = false
    timingError.value = ''
    void loadDetailedTiming()
  },
  { immediate: true },
)

const timedOperations = computed(() =>
  (granularTiming.value?.operations ?? []).filter(
    operation => operation.contributes_to_active_time || operation.metadata?.show_in_timing_table === true,
  )
)

const operationColumns: FileColumn[] = [
  { key: 'operation_type', label: 'Operation', sortable: true },
  { key: 'name', label: 'Name', sortable: true },
  { key: 'stage', label: 'Stage', sortable: true },
  { key: 'aggregation_scope', label: 'Aggregation', sortable: true },
  { key: 'duration_seconds', label: 'Duration', sortable: true },
  { key: 'status', label: 'Status', sortable: true },
]

const operationTableData = computed(() => {
  const operations = granularTiming.value?.operations ?? []
  const operationsById = new Map(operations.map(operation => [operation.operation_id, operation]))

  function aggregationScope(operation: typeof operations[number]): string {
    if (operation.metadata?.time_basis === 'duration_only') return 'Duration only'
    if (!operation.contributes_to_active_time) return 'Detail only'

    const visited = new Set<string>()
    let parentId = operation.parent_id
    while (parentId && !visited.has(parentId)) {
      visited.add(parentId)
      const parent = operationsById.get(parentId)
      if (!parent) break
      if (parent.contributes_to_active_time) return 'Nested (excluded)'
      parentId = parent.parent_id
    }
    return 'Included'
  }

  return timedOperations.value.map(operation => ({
    operation_type: operation.operation_type.replace(/_/g, ' '),
    name: operation.name,
    stage: operation.stage || '\u2014',
    aggregation_scope: aggregationScope(operation),
    duration_seconds: operation.duration_seconds,
    status: operation.status,
  }))
})

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
function statusDotColor(status: string): string {
  const map: Record<string, string> = {
    success: 'var(--nv-success)', degraded: 'var(--nv-warning)', error: 'var(--nv-error)', partial: 'var(--nv-warning)',
    skipped: 'var(--nv-skipped)', not_ran: 'var(--nv-text-tertiary)',
  }
  return map[status] ?? 'var(--nv-text-tertiary)'
}

// --- Stage Timing (CSS flexbox) ---
const collectorStageTiming = computed(() => resolveStageTiming(
  collector.value?.stage_timing,
  manifestStore.timing?.per_dut?.find(entry => entry.dut_id === dutId.value)
    ?.collectors.find(entry => entry.id.toLowerCase() === collector.value?.id.toLowerCase())?.stage_timing,
  stageTimingFromOperations(granularTiming.value),
))
const hasStageData = computed(() =>
  Object.values(collectorStageTiming.value).some(v => v != null)
)

const STAGE_META: Record<string, { color: string; label: string }> = {
  validation: { color: 'rgba(59,130,246,0.85)', label: 'Validation' },
  discovery: { color: 'rgba(124,58,237,0.85)', label: 'Discovery' },
  execution: { color: 'rgba(118,185,0,0.85)', label: 'Execution' },
  post_processing: { color: 'rgba(217,119,6,0.85)', label: 'Post-Processing' },
}

const stageSegments = computed(() => {
  if (!collector.value) return []
  const timing = collectorStageTiming.value
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

const fileSections = computed(() => [
  {
    key: 'artifacts',
    title: 'Collected Artifacts',
    files: partitionedFiles.value.artifacts,
  },
  {
    key: 'diagnostics',
    title: 'Diagnostics',
    files: partitionedFiles.value.diagnostics,
  },
].filter(section => section.files.length > 0))

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

function depRoute(depId: string): RouteLocationRaw {
  const d = dut.value
  if (!d) return '#'
  for (const g of d.collector_groups) {
    if (g.collectors.some(c => c.id === depId)) {
      return collectorDetailRoute(dutId.value, g.name, depId)
    }
  }
  return '#'
}

// --- Utilities ---
function fileName(path: string): string {
  return path.split('/').pop() ?? path
}

function operationStatusBadgeClass(status: string): string {
  const normalized = String(status || '').toLowerCase()
  if (normalized === 'success' || normalized === 'complete') return 'nv-badge--success'
  if (normalized === 'error' || normalized === 'failed') return 'nv-badge--error'
  if (normalized === 'cancelled' || normalized === 'degraded' || normalized === 'partial') return 'nv-badge--warning'
  return 'nv-badge--neutral'
}

function formatArtifactDuration(value: unknown, row: Record<string, any>): string {
  if (typeof value === 'number' && Number.isFinite(value)) return formatDuration(value)
  if (row._measurement_scope === 'shared_operation') return 'Shared operation'
  if (row._measurement) return 'See operation'
  return 'Not instrumented'
}

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}

</script>

<style scoped>
.cd-page { margin-left: 260px; }

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
  flex-wrap: wrap;
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
  overflow-wrap: anywhere;
}
.cd-header__actions { flex-shrink: 0; }

/* ── Compact summary and section navigation ── */
.cd-overview { margin-bottom: 12px; }
.cd-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 32px;
  margin: 0 0 12px;
}
.cd-summary > div { display: flex; align-items: baseline; gap: 8px; }
.cd-summary dt { color: var(--nv-text-secondary); font-size: 0.75rem; }
.cd-summary dd { margin: 0; font-size: 0.875rem; font-weight: 600; }
.cd-stage-title { margin: 0 0 6px; font-size: 0.75rem; color: var(--nv-text-secondary); }
.cd-section-nav {
  position: sticky;
  top: 52px;
  z-index: 3;
  display: flex;
  gap: 8px;
  padding: 6px;
  margin-bottom: 12px;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  background: var(--nv-glass-bg-dense);
  backdrop-filter: var(--nv-glass-blur);
}
.cd-anchor { scroll-margin-top: 116px; margin-bottom: 16px; min-width: 0; }
.cd-operation-table :deep(.dt-scroll) { max-height: 420px; }
.cd-disclosure { margin-bottom: 12px; min-width: 0; }
.cd-disclosure > summary {
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 600;
}
.cd-disclosure[open] > summary { margin-bottom: 16px; }
.cd-help, .cd-empty { color: var(--nv-text-secondary); font-size: 0.8125rem; line-height: 1.5; }
.cd-result { margin: 0 0 12px; }
@media (max-width: 1024px) {
  .cd-page { margin-left: 0; }
}
@media (max-width: 600px) {
  .cd-header { align-items: flex-start; flex-wrap: wrap; padding: 12px; }
  .cd-header__main { gap: 8px; }
  .cd-summary { gap: 8px 16px; }
  .cd-section-nav { gap: 2px; }
  .cd-section-nav .nv-btn { padding-inline: 8px; }
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

/* ── Timing load error ── */
.cd-info-note {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 14px 18px;
  margin-bottom: 16px;
  border-radius: var(--nv-radius-lg);
  border: 1px solid var(--nv-glass-border);
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
  height: 18px;
  border-radius: var(--nv-radius-md);
  overflow: hidden;
  border: 1px solid var(--nv-glass-border);
  margin-bottom: 8px;
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
