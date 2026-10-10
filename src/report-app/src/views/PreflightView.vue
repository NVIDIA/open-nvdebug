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
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: String(dutId), to: dutRoute(dutId) }, { label: 'Preflight Checks' }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">Preflight Checks — {{ dutId }}</h2>

    <div v-if="checks.length === 0" class="nv-empty">No preflight data available.</div>

    <div v-else class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable :columns="columns" :data="checks">
        <template #cell-status="{ value }">
          <StatusBadge :status="value" />
        </template>
        <template #cell-details="{ value }">
          <span style="font-size: 0.75rem; color: var(--nv-text-secondary); word-break: break-word; max-width: 400px; display: inline-block;">
            {{ value != null && typeof value === 'object' ? safeStringify(value) : (value || '\u2014') }}
          </span>
        </template>
      </DataTable>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { dutRoute } from '@/utils/reportRoutes'

function safeStringify(val: unknown): string {
  try { return JSON.stringify(val) } catch { return String(val) }
}

const route = useRoute()
const manifestStore = useManifestStore()

const dutId = computed(() => String(route.params.dutId))

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'name', label: 'Check' },
  { key: 'group', label: 'Group' },
  { key: 'status', label: 'Status' },
  { key: 'details', label: 'Details' },
]

const checks = computed(() => {
  const dutPreflight = manifestStore.preflight?.per_dut.find(p => p.dut_id === dutId.value)
  return dutPreflight?.checks ?? []
})
</script>
