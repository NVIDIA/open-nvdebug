<template>
  <div class="nv-page">
    <div class="nv-grid nv-grid--cards">
      <div v-for="field in fields" :key="field.label" class="nv-card">
        <div class="nv-section-subtitle" style="margin-bottom: 4px;">{{ field.label }}</div>
        <div style="font-size: 0.875rem; font-weight: 600; color: var(--nv-text-primary);">{{ field.value }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ data: any }>()

const fields = computed(() => {
  const d = props.data
  const result: Array<{ label: string; value: string }> = []
  if (d.Name) result.push({ label: 'Name', value: d.Name })
  if (d.Id) result.push({ label: 'ID', value: d.Id })
  if (d.Model) result.push({ label: 'Model', value: d.Model })
  if (d.Manufacturer) result.push({ label: 'Manufacturer', value: d.Manufacturer })
  if (d.SerialNumber) result.push({ label: 'Serial Number', value: d.SerialNumber })
  if (d.PartNumber) result.push({ label: 'Part Number', value: d.PartNumber })
  if (d.FirmwareVersion) result.push({ label: 'Firmware', value: d.FirmwareVersion })
  if (d.BiosVersion) result.push({ label: 'BIOS', value: d.BiosVersion })
  if (d.Status?.Health) result.push({ label: 'Health', value: d.Status.Health })
  if (d.Status?.State) result.push({ label: 'State', value: d.Status.State })
  if (d.PowerState) result.push({ label: 'Power State', value: d.PowerState })
  if (d.SystemType) result.push({ label: 'Type', value: d.SystemType })
  if (d.HostName) result.push({ label: 'Hostname', value: d.HostName })
  if (d.ProcessorSummary?.Count) result.push({ label: 'Processors', value: `${d.ProcessorSummary.Count}x ${d.ProcessorSummary.Model ?? ''}` })
  if (d.MemorySummary?.TotalSystemMemoryGiB) result.push({ label: 'Memory', value: `${d.MemorySummary.TotalSystemMemoryGiB} GiB` })
  if (d.ManagerType) result.push({ label: 'Manager Type', value: d.ManagerType })
  if (d.ChassisType) result.push({ label: 'Chassis Type', value: d.ChassisType })
  if (result.length === 0) result.push({ label: 'Type', value: d['@odata.type'] ?? 'Unknown' })
  return result
})
</script>
