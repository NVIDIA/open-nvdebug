<template>
  <div class="nv-page">
    <!-- Power Consumption Summary -->
    <div v-if="powerControls.length > 0" style="margin-bottom: 24px;">
      <h3 class="nv-section-subtitle">Power Consumption</h3>
      <div class="nv-grid nv-grid--cards">
        <div v-for="pc in powerControls" :key="pc.name" class="nv-stat nv-stat--blue">
          <div class="nv-stat__label">{{ pc.name }}</div>
          <div class="nv-stat__value">{{ pc.consumed != null ? pc.consumed + ' W' : '—' }}</div>
          <div v-if="pc.capacity" class="nv-stat__subtitle">Capacity: {{ pc.capacity }} W</div>
          <div v-if="pc.consumed != null && pc.capacity" class="nv-progress" style="margin-top: 8px; height: 4px;">
            <div
              class="nv-progress__segment"
              :style="{
                width: Math.min((pc.consumed / pc.capacity) * 100, 100) + '%',
                background: powerBarColor(pc.consumed, pc.capacity),
                borderRadius: '2px',
              }"
            />
          </div>
        </div>
      </div>
    </div>

    <!-- Voltages Table -->
    <div v-if="voltages.length > 0" style="margin-bottom: 24px;">
      <h3 class="nv-section-subtitle">Voltages ({{ voltages.length }})</h3>
      <div class="nv-table-viewport" style="max-height: 400px;">
        <table class="nv-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Reading</th>
              <th>Upper Threshold</th>
              <th>Lower Threshold</th>
              <th>Health</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="v in voltages" :key="v.name">
              <td>{{ v.name }}</td>
              <td style="font-weight: 600;">
                <span :style="{ color: voltageColor(v) }">
                  {{ v.reading != null ? v.reading + ' V' : '—' }}
                </span>
              </td>
              <td>{{ v.upper != null ? v.upper + ' V' : '—' }}</td>
              <td>{{ v.lower != null ? v.lower + ' V' : '—' }}</td>
              <td>
                <span
                  v-if="v.health"
                  class="nv-badge"
                  :class="healthBadgeClass(v.health)"
                >{{ v.health }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Power Supplies -->
    <div v-if="psus.length > 0">
      <h3 class="nv-section-subtitle">Power Supplies ({{ psus.length }})</h3>
      <div class="nv-grid nv-grid--cards">
        <div v-for="psu in psus" :key="psu.name" class="nv-sensor-card">
          <div class="nv-log__count" style="margin-left: 0; margin-bottom: 4px;">{{ psu.name }}</div>
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
            <span
              class="psu-indicator"
              :style="{ background: psu.health === 'OK' ? 'var(--nv-success)' : psu.health === 'Warning' ? 'var(--nv-warning)' : 'var(--nv-error)' }"
            />
            <span
              class="nv-badge"
              :class="healthBadgeClass(psu.health ?? 'Unknown')"
            >{{ psu.health ?? 'Unknown' }}</span>
          </div>
          <div v-if="psu.output != null" style="font-size: 1.25rem; font-weight: 700; color: var(--nv-text-primary);">
            {{ psu.output }} W
          </div>
          <div class="psu-details">
            <span v-if="psu.model">{{ psu.model }}</span>
            <span v-if="psu.serialNumber">S/N: {{ psu.serialNumber }}</span>
            <span v-if="psu.type">{{ psu.type }}</span>
            <span v-if="psu.capacity">Cap: {{ psu.capacity }} W</span>
          </div>
        </div>
      </div>
    </div>

    <div v-if="powerControls.length === 0 && voltages.length === 0 && psus.length === 0" class="nv-empty">
      No power data available
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ data: any }>()

interface PowerControl {
  name: string
  consumed: number | null
  capacity: number | null
}

interface Voltage {
  name: string
  reading: number | null
  upper: number | null
  lower: number | null
  health: string | null
}

interface PSU {
  name: string
  health: string | null
  model: string | null
  serialNumber: string | null
  type: string | null
  output: number | null
  capacity: number | null
}

const powerControls = computed<PowerControl[]>(() => {
  const items = props.data?.PowerControl ?? []
  return items.map((pc: any) => ({
    name: pc.Name ?? pc.MemberId ?? 'Power Control',
    consumed: pc.PowerConsumedWatts ?? pc.PowerAvailableWatts ?? null,
    capacity: pc.PowerCapacityWatts ?? pc.PowerAllocatedWatts ?? null,
  }))
})

const voltages = computed<Voltage[]>(() => {
  const items = props.data?.Voltages ?? []
  return items.map((v: any) => ({
    name: v.Name ?? v.MemberId ?? 'Unknown',
    reading: v.ReadingVolts ?? v.Reading ?? null,
    upper: v.UpperThresholdCritical ?? null,
    lower: v.LowerThresholdCritical ?? null,
    health: v.Status?.Health ?? v.Status?.State ?? null,
  }))
})

const psus = computed<PSU[]>(() => {
  const items = props.data?.PowerSupplies ?? []
  return items.map((p: any) => ({
    name: p.Name ?? p.MemberId ?? 'PSU',
    health: p.Status?.Health ?? p.Status?.State ?? null,
    model: p.Model ?? null,
    serialNumber: p.SerialNumber ?? null,
    type: p.PowerSupplyType ?? null,
    output: p.LastPowerOutputWatts ?? p.PowerOutputWatts ?? null,
    capacity: p.PowerCapacityWatts ?? null,
  }))
})

function powerBarColor(consumed: number, capacity: number): string {
  const pct = consumed / capacity
  if (pct >= 0.9) return 'var(--nv-error)'
  if (pct >= 0.75) return 'var(--nv-warning)'
  return 'var(--nv-success)'
}

function voltageColor(v: Voltage): string {
  if (v.reading == null) return 'var(--nv-text-secondary)'
  if (v.upper != null && v.reading >= v.upper) return 'var(--nv-error)'
  if (v.lower != null && v.reading <= v.lower) return 'var(--nv-error)'
  return 'var(--nv-text-primary)'
}

function healthBadgeClass(health: string): string {
  switch (health?.toLowerCase()) {
    case 'ok': return 'nv-badge--success'
    case 'warning': return 'nv-badge--warning'
    case 'critical': return 'nv-badge--error'
    default: return 'nv-badge--neutral'
  }
}
</script>

<style scoped>
.psu-indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.psu-details {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
}
</style>
