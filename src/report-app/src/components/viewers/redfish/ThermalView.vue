<template>
  <div class="nv-page">
    <!-- Temperatures -->
    <div v-if="temperatures.length > 0" style="margin-bottom: 24px;">
      <h3 class="nv-section-subtitle">Temperatures</h3>
      <div class="nv-grid nv-grid--cards">
        <div v-for="sensor in temperatures" :key="sensor.name" class="nv-sensor-card">
          <div class="nv-log__count" style="margin-left: 0; margin-bottom: 4px;">{{ sensor.name }}</div>
          <div :style="{ fontSize: '24px', fontWeight: 700, color: tempColor(sensor.reading, sensor.upper) }">
            {{ sensor.reading != null ? sensor.reading + '\u00B0C' : '\u2014' }}
          </div>
          <!-- Simple bar gauge -->
          <div v-if="sensor.reading != null" class="nv-progress" style="margin-top: 8px; height: 6px;">
            <div class="nv-progress__segment" :style="{ width: Math.min((sensor.reading / (sensor.upper || 100)) * 100, 100) + '%', background: tempColor(sensor.reading, sensor.upper), borderRadius: '3px', transition: 'width 0.3s' }"></div>
          </div>
          <div v-if="sensor.upper" style="font-size: 0.625rem; color: var(--nv-text-secondary); margin-top: 2px;">
            Threshold: {{ sensor.upper }}&deg;C
          </div>
        </div>
      </div>
    </div>

    <!-- Fans -->
    <div v-if="fans.length > 0">
      <h3 class="nv-section-subtitle">Fans</h3>
      <div class="nv-grid nv-grid--cards">
        <div v-for="fan in fans" :key="fan.name" class="nv-sensor-card">
          <div class="nv-log__count" style="margin-left: 0; margin-bottom: 4px;">{{ fan.name }}</div>
          <div style="font-size: 1.5rem; font-weight: 700; color: var(--nv-text-primary);">
            {{ fan.reading != null ? fan.reading + ' RPM' : '\u2014' }}
          </div>
          <div v-if="fan.status" :style="{ fontSize: '11px', color: fan.status === 'OK' ? 'var(--nv-success)' : 'var(--nv-error)' }">
            {{ fan.status }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ data: any }>()

interface SensorReading { name: string; reading: number | null; upper: number | null; status?: string }

const temperatures = computed<SensorReading[]>(() => {
  const temps = props.data?.Temperatures ?? props.data?.Members ?? []
  return temps.map((t: any) => ({
    name: t.Name ?? t.MemberId ?? 'Unknown',
    reading: t.ReadingCelsius ?? t.Reading ?? null,
    upper: t.UpperThresholdCritical ?? t.UpperCritical ?? null,
    status: t.Status?.Health ?? t.Status?.State,
  }))
})

const fans = computed<SensorReading[]>(() => {
  const f = props.data?.Fans ?? []
  return f.map((fan: any) => ({
    name: fan.Name ?? fan.FanName ?? fan.MemberId ?? 'Unknown',
    reading: fan.Reading ?? fan.ReadingRPM ?? null,
    upper: null,
    status: fan.Status?.Health ?? fan.Status?.State,
  }))
})

function tempColor(reading: number | null, upper: number | null): string {
  if (reading == null) return 'var(--nv-text-secondary)'
  if (upper && reading >= upper) return 'var(--nv-error)'
  if (upper && reading >= upper * 0.85) return 'var(--nv-warning)'
  return 'var(--nv-success)'
}
</script>
