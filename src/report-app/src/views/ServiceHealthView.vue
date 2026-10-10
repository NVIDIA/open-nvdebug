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
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>
      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 0; font-size: 0.6875rem;">Services</h4>
      <div style="padding: 4px 0;">
        <a
          v-for="s in serviceList"
          :key="s.name"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': selectedService === s.name }"
          style="font-size: 0.75rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;"
          @click="selectedService = selectedService === s.name ? '' : s.name"
        >
          <span>{{ s.name }}</span>
          <span class="nv-badge" :class="serviceRateBadge(s.lifecycle)" style="font-size: 0.625rem;">{{ serviceRateLabel(s.lifecycle) }}</span>
        </a>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 8px 12px; margin: 8px 0 0; font-size: 0.6875rem;">Filter by DUT</h4>
      <div style="padding: 4px 0; max-height: 200px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': !dutFilter }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = ''"
        >All DUTs</a>
        <a
          v-for="d in manifestStore.duts"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': dutFilter === d.id }"
          style="font-size: 0.75rem; cursor: pointer;"
          @click="dutFilter = d.id"
        >{{ d.id }}</a>
      </div>
    </div>

    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Analyzing service health..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Service Health' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 16px;">Service Health Summary</h2>

        <div class="sh-cards">
          <div v-for="s in displayServices" :key="s.name" class="sh-card nv-glass" @click="selectedService = selectedService === s.name ? '' : s.name">
            <div class="sh-card__header">
              <ServiceBadge :service="s.name" />
              <span class="sh-card__rate" :style="{ color: serviceRateColor(s.lifecycle) }">{{ serviceRateLabel(s.lifecycle, 1) }}</span>
            </div>
            <div class="sh-card__stats">
              <span style="color: var(--nv-success);">{{ s.success }} ok</span>
              <span v-if="s.degraded" style="color: var(--nv-warning);">{{ s.degraded }} degraded</span>
              <span v-if="s.error" style="color: var(--nv-error);">{{ s.error }} err</span>
              <span v-if="s.partial" style="color: var(--nv-warning);">{{ s.partial }} partial</span>
              <span v-if="s.skipped" style="color: var(--nv-text-tertiary);">{{ s.skipped }} skip</span>
              <span v-if="s.cancelled" style="color: var(--nv-warning);">{{ s.cancelled }} cancelled</span>
              <span v-if="s.running" style="color: var(--nv-info);">{{ s.running }} running</span>
              <span v-if="s.pending" style="color: var(--nv-text-tertiary);">{{ s.pending }} pending</span>
            </div>
            <div class="sh-card__bar">
              <div class="sh-card__bar-fill sh-card__bar-fill--success" :style="{ width: pct(s.success, s.total) }"></div>
              <div class="sh-card__bar-fill sh-card__bar-fill--degraded" :style="{ width: pct(s.degraded, s.total) }"></div>
              <div class="sh-card__bar-fill sh-card__bar-fill--error" :style="{ width: pct(s.error, s.total) }"></div>
              <div class="sh-card__bar-fill sh-card__bar-fill--partial" :style="{ width: pct(s.partial, s.total) }"></div>
              <div class="sh-card__bar-fill sh-card__bar-fill--cancelled" :style="{ width: pct(s.cancelled, s.total) }"></div>
            </div>
            <div class="sh-card__meta">
              {{ s.total }} completed
              <template v-if="s.running || s.pending">
                &middot; {{ s.running }} running &middot; {{ s.pending }} pending
              </template>
              &middot; {{ formatDuration(s.totalDuration) }} total &middot; {{ formatDuration(s.avgDuration) }} avg
            </div>
          </div>
        </div>

        <div v-if="selectedService" style="margin-top: 20px;">
          <h3 class="nv-section-title" style="margin-bottom: 12px;">{{ selectedService }} — Per-DUT Breakdown</h3>
          <div class="nv-card">
            <DataTable
              :columns="perDutColumns"
              :data="perDutData"
              :searchable="true"
              @row-click="(row: Record<string, any>) => router.push(dutRoute(row.dutId))"
            >
              <template #cell-successRate="{ row }">
                <span :style="{ color: serviceRateColor(row.lifecycle), fontWeight: 600 }">{{ row.successRateLabel }}</span>
              </template>
            </DataTable>
          </div>
        </div>
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
import ServiceBadge from '@/components/common/ServiceBadge.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import {
  formatCollectorPassRate,
  isTerminalCollectorStatus,
  summarizeCollectorStatuses,
} from '@/utils/collectorLifecycle'
import type {
  CollectorLifecycleCounts,
  CollectorLifecycleSummary,
} from '@/utils/collectorLifecycle'
import { formatDuration } from '@/utils/format'
import { dutRoute } from '@/utils/reportRoutes'

const router = useRouter()
const manifestStore = useManifestStore()
const selectedService = ref('')
const dutFilter = ref('')

interface LifecycleDisplayStats extends CollectorLifecycleCounts {
  lifecycle: CollectorLifecycleSummary
  total: number
  successRate: number | null
  successRateLabel: string
}

interface ServiceStats extends LifecycleDisplayStats {
  name: string
  totalDuration: number
  avgDuration: number
}

const serviceList = computed<ServiceStats[]>(() => {
  const map = new Map<
    string,
    { name: string; statuses: unknown[]; totalDuration: number }
  >()
  const duts = dutFilter.value ? manifestStore.duts.filter(d => d.id === dutFilter.value) : manifestStore.duts
  for (const dut of duts) {
    for (const g of dut.collector_groups) {
      const svc = g.service_type || g.name
      if (!map.has(svc)) {
        map.set(svc, { name: svc, statuses: [], totalDuration: 0 })
      }
      const s = map.get(svc)!
      for (const c of g.collectors) {
        s.statuses.push(c.status)
        if (isTerminalCollectorStatus(c.status)) {
          s.totalDuration += c.execution_time
        }
      }
    }
  }
  return [...map.values()]
    .map(s => {
      const lifecycle = summarizeCollectorStatuses(s.statuses)
      return {
        name: s.name,
        ...lifecycle.counts,
        lifecycle,
        total: lifecycle.completedCount,
        successRate: lifecycle.passRate,
        successRateLabel: formatCollectorPassRate(lifecycle),
        totalDuration: s.totalDuration,
        avgDuration:
          lifecycle.completedCount > 0
            ? s.totalDuration / lifecycle.completedCount
            : 0,
      }
    })
    .sort(
      (a, b) =>
        b.lifecycle.completedCount + b.lifecycle.activeCount -
        (a.lifecycle.completedCount + a.lifecycle.activeCount),
    )
})

const displayServices = computed(() => serviceList.value)

const perDutColumns = [
  { key: 'dutId', label: 'DUT', sortable: true },
  { key: 'success', label: 'Success', sortable: true },
  { key: 'degraded', label: 'Degraded', sortable: true },
  { key: 'error', label: 'Error', sortable: true },
  { key: 'partial', label: 'Partial', sortable: true },
  { key: 'cancelled', label: 'Cancelled', sortable: true },
  { key: 'running', label: 'Running', sortable: true },
  { key: 'pending', label: 'Pending', sortable: true },
  { key: 'total', label: 'Completed', sortable: true },
  { key: 'successRate', label: 'Success Rate', sortable: true },
  { key: 'totalDuration', label: 'Duration', sortable: true },
]

const perDutData = computed(() => {
  if (!selectedService.value) return []
  const rows: Array<LifecycleDisplayStats & {
    dutId: string
    totalDuration: string
  }> = []
  const duts = dutFilter.value ? manifestStore.duts.filter(d => d.id === dutFilter.value) : manifestStore.duts
  for (const dut of duts) {
    const statuses: unknown[] = []
    let duration = 0
    for (const g of dut.collector_groups) {
      if ((g.service_type || g.name) !== selectedService.value) continue
      for (const c of g.collectors) {
        statuses.push(c.status)
        if (isTerminalCollectorStatus(c.status)) {
          duration += c.execution_time
        }
      }
    }
    const lifecycle = summarizeCollectorStatuses(statuses)
    if (lifecycle.completedCount > 0 || lifecycle.activeCount > 0) {
      rows.push({
        dutId: dut.id,
        ...lifecycle.counts,
        lifecycle,
        total: lifecycle.completedCount,
        successRate: lifecycle.passRate,
        successRateLabel: formatCollectorPassRate(lifecycle, 1),
        totalDuration: formatDuration(duration),
      })
    }
  }
  return rows
})

function serviceRateLabel(
  lifecycle: CollectorLifecycleSummary,
  fractionDigits = 0,
) {
  return formatCollectorPassRate(lifecycle, fractionDigits)
}

function serviceRateColor(lifecycle: CollectorLifecycleSummary) {
  if (lifecycle.state === 'in_progress') return 'var(--nv-info)'
  if (lifecycle.passRate === null) return 'var(--nv-text-tertiary)'
  if (lifecycle.passRate >= 90) return 'var(--nv-success)'
  if (lifecycle.passRate >= 50) return 'var(--nv-warning)'
  return 'var(--nv-error)'
}

function serviceRateBadge(lifecycle: CollectorLifecycleSummary) {
  if (lifecycle.state === 'in_progress') return 'nv-badge--running'
  if (lifecycle.passRate === null) return 'nv-badge--neutral'
  if (lifecycle.passRate >= 90) return 'nv-badge--success'
  if (lifecycle.passRate >= 50) return 'nv-badge--warning'
  return 'nv-badge--error'
}

function pct(n: number, total: number) {
  return total > 0 ? `${(n / total) * 100}%` : '0%'
}

</script>

<style scoped>
.sh-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.sh-card {
  padding: 14px 16px;
  border-radius: var(--nv-radius-lg);
  cursor: pointer;
  transition: box-shadow var(--nv-duration-base) var(--nv-ease), transform var(--nv-duration-base) var(--nv-ease);
}
.sh-card:hover {
  box-shadow: var(--nv-glass-shadow);
  transform: translateY(-1px);
}
.sh-card__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.sh-card__rate {
  font-size: 1.25rem;
  font-weight: 700;
  font-family: var(--nv-font-mono);
}
.sh-card__stats {
  display: flex;
  gap: 8px;
  font-size: 0.6875rem;
  font-weight: 600;
  margin-bottom: 8px;
}
.sh-card__bar {
  height: 4px;
  border-radius: 2px;
  background: var(--nv-glass-bg-light);
  display: flex;
  overflow: hidden;
  margin-bottom: 6px;
}
.sh-card__bar-fill { height: 100%; }
.sh-card__bar-fill--success { background: var(--nv-success); }
.sh-card__bar-fill--degraded { background: var(--nv-warning); }
.sh-card__bar-fill--error { background: var(--nv-error); }
.sh-card__bar-fill--partial { background: var(--nv-warning); }
.sh-card__bar-fill--cancelled { background: var(--nv-skipped); }
.sh-card__meta {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
}
</style>
