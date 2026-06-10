<template>
  <div class="nv-page">
    <div v-if="drives.length === 0" class="nv-empty">
      No storage drive data available
    </div>

    <template v-else>
      <h3 class="nv-section-subtitle">Drives ({{ drives.length }})</h3>
      <div class="nv-grid nv-grid--cards">
        <div v-for="drive in drives" :key="drive.id" class="nv-card drive-card">
          <!-- Health indicator strip -->
          <div class="drive-health-strip" :style="{ background: healthColor(drive.health) }" />

          <div class="drive-header">
            <span style="font-weight: 600; color: var(--nv-text-primary);">{{ drive.name }}</span>
            <span
              class="nv-badge"
              :class="healthBadge(drive.health)"
            >{{ drive.health || 'Unknown' }}</span>
          </div>

          <div class="drive-meta">
            <div v-if="drive.capacity" class="drive-meta__row">
              <span class="drive-meta__label">Capacity</span>
              <span class="drive-meta__value">{{ drive.capacity }}</span>
            </div>
            <div v-if="drive.mediaType" class="drive-meta__row">
              <span class="drive-meta__label">Type</span>
              <span class="drive-meta__value">{{ drive.mediaType }}</span>
            </div>
            <div v-if="drive.model" class="drive-meta__row">
              <span class="drive-meta__label">Model</span>
              <span class="drive-meta__value">{{ drive.model }}</span>
            </div>
            <div v-if="drive.manufacturer" class="drive-meta__row">
              <span class="drive-meta__label">Mfr</span>
              <span class="drive-meta__value">{{ drive.manufacturer }}</span>
            </div>
            <div v-if="drive.serialNumber" class="drive-meta__row">
              <span class="drive-meta__label">S/N</span>
              <span class="drive-meta__value mono" style="font-size: 0.6875rem;">{{ drive.serialNumber }}</span>
            </div>
            <div v-if="drive.protocol" class="drive-meta__row">
              <span class="drive-meta__label">Protocol</span>
              <span class="drive-meta__value">{{ drive.protocol }}</span>
            </div>
          </div>

          <!-- Predicted media life (if available) -->
          <div v-if="drive.lifeLeft != null" style="margin-top: 8px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.625rem; color: var(--nv-text-tertiary); margin-bottom: 2px;">
              <span>Life remaining</span>
              <span>{{ drive.lifeLeft }}%</span>
            </div>
            <div class="nv-progress" style="height: 4px;">
              <div
                class="nv-progress__segment"
                :style="{
                  width: drive.lifeLeft + '%',
                  background: lifeColor(drive.lifeLeft),
                  borderRadius: '2px',
                }"
              />
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ data: any }>()

interface Drive {
  id: string
  name: string
  health: string
  capacity: string | null
  mediaType: string | null
  model: string | null
  manufacturer: string | null
  serialNumber: string | null
  protocol: string | null
  lifeLeft: number | null
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return (bytes / 1e12).toFixed(1) + ' TB'
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB'
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB'
  return bytes + ' B'
}

const drives = computed<Drive[]>(() => {
  let items = props.data?.Drives ?? props.data?.Members ?? []
  if (!Array.isArray(items) && props.data?.['@odata.type']?.includes('Drive')) {
    items = [props.data]
  }
  return items.map((d: any) => ({
    id: d.Id ?? d['@odata.id'] ?? d.Name ?? Math.random().toString(),
    name: d.Name ?? d.Id ?? 'Drive',
    health: d.Status?.Health ?? d.Status?.State ?? '',
    capacity: d.CapacityBytes ? formatBytes(d.CapacityBytes) : null,
    mediaType: d.MediaType ?? null,
    model: d.Model ?? null,
    manufacturer: d.Manufacturer ?? null,
    serialNumber: d.SerialNumber ?? null,
    protocol: d.Protocol ?? null,
    lifeLeft: d.PredictedMediaLifeLeftPercent ?? null,
  }))
})

function healthColor(health: string): string {
  switch (health?.toLowerCase()) {
    case 'ok': return 'var(--nv-success)'
    case 'warning': return 'var(--nv-warning)'
    case 'critical': return 'var(--nv-error)'
    default: return 'var(--nv-text-tertiary)'
  }
}

function healthBadge(health: string): string {
  switch (health?.toLowerCase()) {
    case 'ok': return 'nv-badge--success'
    case 'warning': return 'nv-badge--warning'
    case 'critical': return 'nv-badge--error'
    default: return 'nv-badge--neutral'
  }
}

function lifeColor(pct: number): string {
  if (pct <= 10) return 'var(--nv-error)'
  if (pct <= 30) return 'var(--nv-warning)'
  return 'var(--nv-success)'
}
</script>

<style scoped>
.drive-card {
  position: relative;
  overflow: hidden;
  padding-top: calc(var(--nv-space-4) + 3px);
}

.drive-health-strip {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
}

.drive-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.drive-meta {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.drive-meta__row {
  display: flex;
  justify-content: space-between;
  font-size: 0.75rem;
}

.drive-meta__label {
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
}

.drive-meta__value {
  color: var(--nv-text-primary);
  text-align: right;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-left: 8px;
}
</style>
