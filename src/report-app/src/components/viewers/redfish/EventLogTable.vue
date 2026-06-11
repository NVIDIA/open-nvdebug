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
