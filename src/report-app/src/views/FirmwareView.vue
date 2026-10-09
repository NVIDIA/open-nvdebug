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
    <Breadcrumbs :items="[{ label: 'Home', to: '/' }, { label: String(dutId), to: dutRoute(dutId) }, { label: 'Firmware' }]" />
    <h2 class="nv-page__title" style="margin: 12px 0 16px;">Firmware — {{ dutId }}</h2>

    <div v-if="firmware.length === 0" class="nv-empty">No firmware data available.</div>

    <div v-else class="nv-glass" style="padding: var(--nv-space-4);">
      <DataTable :columns="columns" :data="firmware" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import { dutRoute } from '@/utils/reportRoutes'

const route = useRoute()
const manifestStore = useManifestStore()

const dutId = computed(() => String(route.params.dutId))

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  { key: 'version', label: 'Version' },
]

const firmware = computed(() => {
  const dut = manifestStore.dutById(dutId.value)
  return (dut?.system_info?.firmware ?? []).map(f => ({
    id: f.id || f.component || '\u2014',
    name: f.name || f.id || f.component || '\u2014',
    version: f.version || '\u2014',
  }))
})
</script>
