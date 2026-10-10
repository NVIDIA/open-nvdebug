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
  <section
    v-if="analysis"
    class="nv-glass resource-summary"
    aria-labelledby="resource-summary-title"
    data-testid="resource-usage-summary"
  >
    <div class="resource-summary__header">
      <div>
        <h3 id="resource-summary-title" class="nv-section-title">Resource Usage</h3>
        <p>Bounded process metrics; average CPU includes completed children when recorded.</p>
      </div>
      <router-link :to="{ name: 'resources' }" class="resource-summary__link">
        Detailed analysis <span aria-hidden="true">&rarr;</span>
      </router-link>
    </div>

    <div class="resource-summary__metrics">
      <StatCard
        label="Peak RSS"
        :value="formatMaybeBytes(analysis.kpis.peakRssBytes)"
        subtitle="Highest summary RSS recorded"
        color="emerald"
      />
      <StatCard
        label="Average CPU"
        :value="formatMaybeCores(analysis.kpis.averageCpuCores)"
        subtitle="Process and completed children"
        color="purple"
      />
      <StatCard
        label="Physical I/O"
        :value="formatPhysicalIo(analysis.kpis.physicalReadBytes, analysis.kpis.physicalWriteBytes)"
        subtitle="Storage-submitted read / write bytes"
        color="blue"
      />
      <StatCard
        label="Sampling health"
        :value="samplingHealth.value"
        :subtitle="samplingHealth.subtitle"
        :color="samplingHealth.color"
      />
      <StatCard
        label="Pressure signals"
        :value="pressureHealth.value"
        :subtitle="pressureHealth.subtitle"
        :color="pressureHealth.color"
      />
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import StatCard from '@/components/dashboard/StatCard.vue'
import {
  RESOURCE_USAGE_PATH,
  loadResourceUsageSummary,
} from '@/services/resourceUsageLoader'
import { useFileSystemStore } from '@/stores/fileSystem'
import type { ResourceUsageAnalysis } from '@/types/resourceUsage'
import { analyzeResourceUsage } from '@/utils/resourceUsage'

interface HealthDisplay {
  value: string
  subtitle: string
  color: string
}

const KIB = 1024
const MIB = 1024 * KIB
const GIB = 1024 * MIB

const fileSystemStore = useFileSystemStore()
const analysis = ref<ResourceUsageAnalysis | null>(null)
let loadGeneration = 0
let activeLoadController: AbortController | null = null

const waitingForDirectory = computed(
  () => fileSystemStore.mode === 'file' && !fileSystemStore.directoryLoaded,
)
const selectedSummaryFile = computed(
  () => fileSystemStore.mode === 'file'
    ? fileSystemStore.fileMap.get(RESOURCE_USAGE_PATH) ?? null
    : null,
)

const samplingHealth = computed<HealthDisplay>(() => {
  const current = analysis.value
  if (!current) return unavailableHealth()

  const health = current.health
  const statusIssue = health.status !== 'unknown' && health.status !== 'completed'
  const hasEvidence = health.samplesReported !== null
    || health.samplesRetained !== null
    || health.scheduledPeriodicSamples !== null
    || health.artifactWriteSucceeded !== null
    || health.sampleWriteFailures !== null
    || health.missedScheduledIntervals !== null
    || current.monitorErrors.length > 0

  const hasIssue = (health.sampleWriteFailures ?? 0) > 0
    || (health.missedScheduledIntervals ?? 0) > 0
    || current.monitorErrors.length > 0
    || health.artifactWriteSucceeded === false
    || statusIssue
  if (hasIssue) {
    return {
      value: 'Review',
      subtitle: 'Producer reported one or more sampling issues',
      color: 'orange',
    }
  }
  if (!hasEvidence) return unavailableHealth()
  return {
    value: health.status === 'completed' ? 'Complete' : 'Available',
    subtitle: 'No producer sampling issues reported',
    color: 'green',
  }
})

const pressureHealth = computed<HealthDisplay>(() => {
  const current = analysis.value
  if (!current) return unavailableHealth()
  const states = [
    current.signals.cpuPressureState,
    current.signals.memoryPressureState,
  ]
  if (states.includes('critical')) {
    return { value: 'Critical', subtitle: 'Recorded pressure signals need review', color: 'red' }
  }
  if (states.includes('observed')) {
    return { value: 'Observed', subtitle: 'Recorded pressure signals need review', color: 'orange' }
  }
  if (states.includes('clear')) {
    return { value: 'Not observed', subtitle: 'Available pressure signals stayed clear', color: 'green' }
  }
  return unavailableHealth('Pressure metrics unavailable')
})

function unavailableHealth(subtitle = 'Sampling metadata unavailable'): HealthDisplay {
  return { value: 'Unavailable', subtitle, color: 'blue' }
}

async function loadSummary(signal?: AbortSignal): Promise<void> {
  const generation = ++loadGeneration
  analysis.value = null
  if (waitingForDirectory.value) return

  try {
    const loaded = await loadResourceUsageSummary({
      mode: fileSystemStore.mode,
      fileMap: fileSystemStore.fileMap,
      signal,
    })
    if (generation !== loadGeneration) return
    analysis.value = analyzeResourceUsage({
      artifact: loaded.artifact,
      samples: loaded.samples,
      diagnostics: loaded.diagnostics,
    })
  } catch {
    // Missing, invalid, or unreadable telemetry must not block the dashboard,
    // and untrusted producer or filesystem details must never be rendered.
    if (signal?.aborted || generation !== loadGeneration) return
    analysis.value = null
  }
}

function startSummaryLoad(): void {
  activeLoadController?.abort()
  const controller = new AbortController()
  activeLoadController = controller
  void loadSummary(controller.signal).finally(() => {
    if (activeLoadController === controller) activeLoadController = null
  })
}

watch(
  [
    () => fileSystemStore.mode,
    () => fileSystemStore.directoryLoaded,
    selectedSummaryFile,
  ],
  startSummaryLoad,
  { immediate: true },
)

onBeforeUnmount(() => {
  loadGeneration++
  activeLoadController?.abort()
  activeLoadController = null
})

function formatMaybeBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return 'Unavailable'
  if (value < KIB) return `${Math.round(value)} B`
  if (value < MIB) return `${(value / KIB).toFixed(1)} KiB`
  if (value < GIB) return `${(value / MIB).toFixed(1)} MiB`
  return `${(value / GIB).toFixed(1)} GiB`
}

function formatMaybeCores(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return 'Unavailable'
  return `${value.toFixed(value < 10 ? 2 : 1)} cores`
}

function formatPhysicalIo(readBytes: number | null, writeBytes: number | null): string {
  if (readBytes === null && writeBytes === null) return 'Unavailable'
  return `R ${formatMaybeBytes(readBytes)} / W ${formatMaybeBytes(writeBytes)}`
}
</script>

<style scoped>
.resource-summary {
  padding: 16px 20px;
  margin-bottom: 16px;
}

.resource-summary__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 12px;
}

.resource-summary__header h3,
.resource-summary__header p {
  margin: 0;
}

.resource-summary__header p {
  margin-top: 3px;
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
}

.resource-summary__link {
  flex-shrink: 0;
  color: var(--nv-accent);
  font-size: 0.75rem;
  font-weight: 600;
  text-decoration: none;
}

.resource-summary__metrics {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
}

@media (max-width: 1200px) {
  .resource-summary__metrics {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}

@media (max-width: 720px) {
  .resource-summary__header {
    flex-direction: column;
  }

  .resource-summary__metrics {
    grid-template-columns: 1fr;
  }
}
</style>
