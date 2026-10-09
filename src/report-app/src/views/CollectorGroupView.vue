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
    <!-- Left Sidebar -->
    <div class="nv-sidebar">
      <div class="nv-sidebar__section">
        <h3 class="nv-page__title" style="font-size: 1rem; margin-bottom: 4px;">Node: {{ dut?.id }}</h3>
        <StatusBadge v-if="dut" :status="dut.overall_status" />
      </div>

      <div class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">Collector Groups</h4>
        <div v-for="g in dut?.collector_groups" :key="g.name" style="margin-bottom: 4px;">
          <router-link :to="collectorGroupRoute(dutId, g.name)" :class="['nv-sidebar__link', { 'nv-sidebar__link--active': g.name === groupName }]">
            <ServiceBadge :service="g.name" />
            <span class="nv-badge nv-badge--neutral" style="margin-left: auto;">{{ g.collectors.length }}</span>
          </router-link>
        </div>
      </div>

      <!-- Collectors in this group -->
      <div v-if="group" class="nv-sidebar__section">
        <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 4px 8px; border-radius: var(--nv-radius-sm); margin-bottom: 8px;">
          {{ groupName }} Collectors
        </h4>
        <router-link
          v-for="c in sidebarCollectors"
          :key="c.id"
          :to="collectorDetailRoute(dutId, groupName, c.id)"
          class="nv-sidebar__link"
          style="font-size: 0.6875rem; padding: 3px 0; display: flex; align-items: center; gap: 6px;"
        >
          <span :style="{ color: statusDotColor(c.status), fontSize: '8px' }">&#9679;</span>
          <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{{ c.id }} — {{ c.name }}</span>
        </router-link>
      </div>
    </div>

    <!-- Main Content -->
    <div class="nv-page" style="margin-left: 260px;">
      <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: dutId, to: dutRoute(dutId) }, { label: groupName }]" />
      <h2 class="nv-page__title" style="margin: 12px 0 16px;">
        <ServiceBadge :service="groupName" /> Collectors — {{ dutId }}
      </h2>

      <div
        v-if="groupMetadataVisible"
        class="nv-glass nv-glass--subtle"
        data-testid="collector-group-metadata"
        style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 8px 12px; margin-bottom: 16px; font-size: 0.75rem; color: var(--nv-text-secondary);"
      >
        <span v-if="group?.access_path"><strong>Access path:</strong> {{ formatAccessPath(group.access_path) }}</span>
        <template v-if="group?.component_labels?.length">
          <strong>Components:</strong>
          <span v-for="label in group.component_labels" :key="label" class="nv-badge nv-badge--neutral">{{ label }}</span>
        </template>
      </div>

      <!-- Group Preflight Checks -->
      <div v-if="groupPreflightChecks.length > 0" class="nv-glass nv-glass--subtle" style="padding: var(--nv-space-4); margin-bottom: 16px;">
        <h4 class="nv-chart-card__title">Preflight Checks ({{ groupName }})</h4>
        <div class="nv-table-viewport">
          <table class="nv-table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="check in groupPreflightChecks" :key="check.name">
                <td>{{ check.name }}</td>
                <td><StatusBadge :status="check.status" /></td>
                <td style="color: var(--nv-text-secondary); font-size: 0.75rem;">{{ check.details || '\u2014' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Group Dependency Checks -->
      <div v-if="groupDependencyChecks.length > 0" class="nv-glass nv-glass--subtle" style="padding: var(--nv-space-4); margin-bottom: 16px;">
        <h4 class="nv-chart-card__title">
          Dependencies ({{ groupName }})
          <span class="nv-badge nv-badge--neutral" style="margin-left: 8px;">{{ groupDependencyChecks.length }} checked</span>
        </h4>
        <DependencyTable v-if="groupHasDeps" :collectors="groupDependencyChecks" />
        <div v-else style="font-size: 0.8125rem; color: var(--nv-text-secondary);">
          No dependency requirements found across {{ groupDependencyChecks.length }} checked collector{{ groupDependencyChecks.length !== 1 ? 's' : '' }} in this group. All ran independently.
        </div>
      </div>

      <!-- Not-ran toggle + Collector Table -->
      <div class="nv-glass" style="padding: var(--nv-space-4);">
        <div v-if="notRanCount > 0" style="display: flex; align-items: center; justify-content: flex-end; margin-bottom: 8px;">
          <label style="display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: var(--nv-text-secondary); cursor: pointer;">
            <input type="checkbox" v-model="showNotRan" style="accent-color: var(--nv-accent);" />
            Show not executed
            <span class="nv-badge nv-badge--neutral">{{ notRanCount }} not ran</span>
          </label>
        </div>
        <DataTable
          :columns="columns"
          :data="visibleCollectors"
          :searchable="true"
          @row-click="(row) => router.push(collectorDetailRoute(dutId, groupName, row.id))"
        >
          <template #cell-status="{ value }">
            <StatusBadge :status="value" />
          </template>
          <template #cell-execution_time="{ value }">
            {{ formatDuration(value) }}
          </template>
          <template #cell-reason="{ value }">
            <ReasonDisplay v-if="value" :text="typeof value === 'object' ? (value?.message || JSON.stringify(value)) : String(value)" :compact="true" />
            <span v-else style="color: var(--nv-text-tertiary); font-size: 0.75rem;">&mdash;</span>
          </template>
          <template #cell-files="{ row }">
            <template v-if="row._files && row._files.length > 0">
              <router-link
                v-for="f in row._files.slice(0, 2)"
                :key="f.path"
                :to="`/file/${encodeURIComponent(f.path)}`"
                style="display: block; font-size: 0.6875rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 250px;"
                @click.stop
              >{{ f.path.split('/').pop() }}</router-link>
              <span v-if="row._files.length > 2" style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">+{{ row._files.length - 2 }} more</span>
            </template>
            <span v-else style="color: var(--nv-text-tertiary);">&mdash;</span>
          </template>
        </DataTable>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import DependencyTable from '@/components/common/DependencyTable.vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import { dedupFiles } from '@/utils/dedupFiles'
import { formatDuration } from '@/utils/format'
import { formatAccessPath } from '@/utils/reportMetadata'
import { collectorDetailRoute, collectorGroupRoute, dutRoute } from '@/utils/reportRoutes'

const route = useRoute()
const router = useRouter()
const manifestStore = useManifestStore()

const dutId = computed(() => String(route.params.dutId))
const groupName = computed(() => String(route.params.group))
const dut = computed(() => manifestStore.dutById(dutId.value))

const group = computed(() => {
  const d = dut.value
  if (!d) return undefined
  const gn = groupName.value.toLowerCase()
  return d.collector_groups.find(g => g.name.toLowerCase() === gn)
})

const groupMetadataVisible = computed(() =>
  group.value?.access_path !== undefined || Boolean(group.value?.component_labels?.length)
)

const showNotRan = ref(false)

function statusDotColor(status: string): string {
  const map: Record<string, string> = {
    success: 'var(--nv-success)', degraded: 'var(--nv-warning)', error: 'var(--nv-error)', partial: 'var(--nv-warning)',
    skipped: 'var(--nv-skipped)', not_ran: 'var(--nv-text-tertiary)',
  }
  return map[status] ?? 'var(--nv-text-tertiary)'
}

interface Column { key: string; label: string; formatter?: (value: unknown, row: Record<string, unknown>) => string }
const hasCollectorComponentMetadata = computed(() =>
  (group.value?.collectors ?? []).some(collector => Boolean(collector.component_label))
)
const hasCollectorAccessMetadata = computed(() =>
  (group.value?.collectors ?? []).some(collector => collector.access_path !== undefined)
)
const columns = computed<Column[]>(() => [
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  ...(hasCollectorComponentMetadata.value ? [{ key: 'component_label', label: 'Component' }] : []),
  ...(hasCollectorAccessMetadata.value ? [{ key: 'access_path', label: 'Access Path' }] : []),
  { key: 'status', label: 'Status' },
  { key: 'execution_time', label: 'Exec Time', formatter: value => formatDuration(Number(value ?? 0)) },
  { key: 'reason', label: 'Reason' },
  { key: 'files', label: 'Files' },
])

const collectors = computed(() =>
  (group.value?.collectors ?? []).map(c => {
    const uniqueFiles = dedupFiles(c.files)
    return {
      id: c.id,
      name: c.name,
      component_label: c.component_label ?? '',
      access_path: c.access_path ? formatAccessPath(c.access_path) : '',
      status: c.status,
      execution_time: c.execution_time,
      // Successful empty collections carry useful evidence (for example,
      // "endpoint queried; no entries found"). Preserve that note instead of
      // hiding every success reason behind an em dash.
      reason: c.reason || '\u2014',
      files: uniqueFiles.length,
      _files: uniqueFiles,
    }
  })
)

const notRanCount = computed(() =>
  collectors.value.filter(c => c.status === 'not_ran').length
)

const visibleCollectors = computed(() => {
  if (showNotRan.value) return collectors.value
  return collectors.value.filter(c => c.status !== 'not_ran')
})

const sidebarCollectors = computed(() => {
  const all = group.value?.collectors ?? []
  if (showNotRan.value) return all
  return all.filter(c => c.status !== 'not_ran')
})

const groupPreflightChecks = computed(() => {
  const preflight = manifestStore.manifest?.preflight?.per_dut ?? []
  const dutPreflight = preflight.find((p: any) => p.dut_id === dutId.value)
  if (!dutPreflight?.checks) return []
  return dutPreflight.checks.filter((c: any) =>
    c.group?.toLowerCase() === groupName.value.toLowerCase() || c.name?.toLowerCase() === groupName.value.toLowerCase()
  )
})

const groupDependencyChecks = computed(() => {
  const deps = manifestStore.manifest?.dependency_check?.per_dut ?? []
  const dutDeps = deps.find((d: any) => d.dut_id === dutId.value)
  if (!dutDeps?.collectors) return []
  const collectorIds = new Set((group.value?.collectors ?? []).map(c => c.id))
  return dutDeps.collectors.filter((d: any) => collectorIds.has(d.collector_id))
})

const groupHasDeps = computed(() =>
  groupDependencyChecks.value.some((d: any) => d.dependencies && d.dependencies.length > 0)
)
</script>
