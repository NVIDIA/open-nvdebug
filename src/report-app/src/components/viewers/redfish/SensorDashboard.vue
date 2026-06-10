<template>
  <div class="nv-page">
    <div v-if="groupedSensors.length === 0" class="nv-empty">
      No sensor data available
    </div>

    <div v-for="group in groupedSensors" :key="group.type" style="margin-bottom: 24px;">
      <h3 class="nv-section-subtitle">{{ group.type }} ({{ group.sensors.length }})</h3>
      <div class="nv-grid nv-grid--cards">
        <div v-for="sensor in group.sensors" :key="sensor.name" class="nv-sensor-card">
          <div class="nv-log__count" style="margin-left: 0; margin-bottom: 4px;">{{ sensor.name }}</div>
          <div
            :style="{
              fontSize: '22px',
              fontWeight: 700,
              color: statusColor(sensor.health),
            }"
          >
            {{ sensor.reading != null ? sensor.reading + ' ' + sensor.unit : '—' }}
          </div>
          <div style="display: flex; align-items: center; gap: 6px; margin-top: 6px;">
            <span
              class="sensor-dot"
              :style="{ background: statusColor(sensor.health) }"
            />
            <span
              class="nv-badge"
              :class="healthBadge(sensor.health)"
              style="font-size: 0.625rem;"
            >{{ sensor.health || 'N/A' }}</span>
          </div>
          <div v-if="sensor.thresholdUpper != null || sensor.thresholdLower != null" class="sensor-thresholds">
            <span v-if="sensor.thresholdLower != null">Low: {{ sensor.thresholdLower }}</span>
            <span v-if="sensor.thresholdUpper != null">High: {{ sensor.thresholdUpper }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ data: any }>()

interface Sensor {
  name: string
  type: string
  reading: number | null
  unit: string
  health: string
  thresholdUpper: number | null
  thresholdLower: number | null
}

const TYPE_ORDER = ['Temperature', 'Voltage', 'Power', 'Fan', 'Other']

const UNIT_MAP: Record<string, string> = {
  Temperature: '°C',
  Voltage: 'V',
  Power: 'W',
  Fan: 'RPM',
  Percent: '%',
  Rotational: 'RPM',
}

const allSensors = computed<Sensor[]>(() => {
  const members = props.data?.Members ?? (Array.isArray(props.data) ? props.data : [])
  return members.map((s: any) => {
    const readingType = s.ReadingType ?? s.PhysicalContext ?? ''
    const type = categorize(readingType)
    return {
      name: s.Name ?? s.MemberId ?? 'Unknown',
      type,
      reading: s.Reading ?? s.ReadingCelsius ?? s.ReadingVolts ?? null,
      unit: s.ReadingUnits ?? UNIT_MAP[type] ?? '',
      health: s.Status?.Health ?? s.Status?.State ?? '',
      thresholdUpper: s.Thresholds?.UpperCritical?.Reading ?? s.UpperThresholdCritical ?? null,
      thresholdLower: s.Thresholds?.LowerCritical?.Reading ?? s.LowerThresholdCritical ?? null,
    }
  })
})

const groupedSensors = computed(() => {
  const map = new Map<string, Sensor[]>()
  for (const sensor of allSensors.value) {
    const list = map.get(sensor.type) ?? []
    list.push(sensor)
    map.set(sensor.type, list)
  }
  return TYPE_ORDER
    .filter(t => map.has(t))
    .map(t => ({ type: t, sensors: map.get(t)! }))
    .concat(
      [...map.entries()]
        .filter(([t]) => !TYPE_ORDER.includes(t))
        .map(([t, sensors]) => ({ type: t, sensors }))
    )
})

function categorize(readingType: string): string {
  const lower = readingType.toLowerCase()
  if (lower.includes('temp') || lower.includes('celsius')) return 'Temperature'
  if (lower.includes('volt')) return 'Voltage'
  if (lower.includes('power') || lower.includes('watt')) return 'Power'
  if (lower.includes('fan') || lower.includes('rotational') || lower.includes('rpm')) return 'Fan'
  if (lower.includes('percent')) return 'Other'
  return readingType || 'Other'
}

function statusColor(health: string): string {
  switch (health?.toLowerCase()) {
    case 'ok': return 'var(--nv-success)'
    case 'warning': return 'var(--nv-warning)'
    case 'critical': return 'var(--nv-error)'
    default: return 'var(--nv-text-secondary)'
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
</script>

<style scoped>
.sensor-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

.sensor-thresholds {
  display: flex;
  gap: 12px;
  margin-top: 6px;
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
}
</style>
