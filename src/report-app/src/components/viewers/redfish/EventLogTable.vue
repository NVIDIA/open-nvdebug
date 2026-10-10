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
    <h3 class="nv-section-subtitle">Event Log ({{ entries.length }} entries)</h3>
    <DataTable :columns="columns" :data="entries" :searchable="true">
      <template #cell-severity="{ value }">
        <span :style="{ fontWeight: 600, color: severityColor(value) }">{{ value }}</span>
      </template>
    </DataTable>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import DataTable from '@/components/common/DataTable.vue'

const props = defineProps<{ data: any }>()

interface Column { key: string; label: string }
const columns: Column[] = [
  { key: 'id', label: 'ID' },
  { key: 'severity', label: 'Severity' },
  { key: 'created', label: 'Created' },
  { key: 'entryType', label: 'Type' },
  { key: 'message', label: 'Message' },
]

const entries = computed(() => {
  const members = props.data?.Members ?? (Array.isArray(props.data) ? props.data : [])
  return members.map((e: any) => ({
    id: e.Id ?? e['@odata.id']?.split('/').pop() ?? '\u2014',
    severity: e.Severity ?? e.MessageSeverity ?? '\u2014',
    created: e.Created ?? e.EventTimestamp ?? '\u2014',
    entryType: e.EntryType ?? '\u2014',
    message: e.Message ?? e.MessageId ?? '\u2014',
  }))
})

function severityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'var(--nv-error)'
    case 'warning': return 'var(--nv-warning)'
    case 'ok': return 'var(--nv-success)'
    default: return 'var(--nv-text-secondary)'
  }
}
</script>
