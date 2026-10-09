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
  <div class="nv-page">
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: pageTitle }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">
      <StatusBadge v-if="statusType !== 'all'" :status="statusType" /> {{ pageTitle }}
    </h2>

    <div class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable
        :columns="columns"
        :data="filteredCollectors"
        :searchable="true"
        @row-click="(row) => router.push(collectorDetailRoute(row.dut_id, row.group, row.id))"
      >
        <template #cell-status="{ value }">
          <StatusBadge :status="value" />
        </template>
        <template #cell-execution_time="{ value }">
          {{ typeof value === 'number' ? value.toFixed(1) + 's' : '\u2014' }}
        </template>
        <template #cell-reason="{ value }">
          <ReasonDisplay :text="value" :compact="true" />
        </template>
      </DataTable>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import { normalizeCollectorStatus } from '@/utils/collectorLifecycle'
import { collectorDetailRoute } from '@/utils/reportRoutes'

const route = useRoute()
const router = useRouter()
const manifestStore = useManifestStore()

const statusType = computed(() => String(route.params.statusType))
const isAll = computed(() => statusType.value === 'all')
const pageTitle = computed(() => isAll.value ? 'All Collectors' : `${statusType.value} Collectors`)

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'dut_id', label: 'DUT' },
  { key: 'group', label: 'Group' },
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  { key: 'execution_time', label: 'Exec Time' },
  { key: 'status', label: 'Status' },
  { key: 'reason', label: 'Reason' },
]

const filteredCollectors = computed(() => {
  const result: any[] = []
  for (const dut of manifestStore.duts) {
    for (const group of dut.collector_groups) {
      for (const c of group.collectors) {
        const status = normalizeCollectorStatus(c.status)
        if (isAll.value || status === normalizeCollectorStatus(statusType.value)) {
          result.push({
            dut_id: dut.id, group: group.name, id: c.id, name: c.name,
            execution_time: c.execution_time, status, reason: c.reason || '',
          })
        }
      }
    }
  }
  return result
})
</script>
