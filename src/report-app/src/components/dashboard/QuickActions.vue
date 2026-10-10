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
  <div class="nv-card">
    <h4 class="nv-section-title" style="margin-bottom: 12px;">Quick Actions &amp; Tools</h4>

    <div class="qa-tools">
      <router-link to="/timing" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M8 4v4l3 2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        Timing Analysis
      </router-link>
      <router-link to="/resources" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M2 13V8m4 5V3m4 10V6m4 7V1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        Resource Usage
      </router-link>
      <router-link to="/file-map" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M2 2h5l2 2h5v10H2V2z" stroke="currentColor" stroke-width="1.5"/></svg>
        File Map
      </router-link>
      <router-link to="/errors" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 1L15 14H1L8 1z" stroke="currentColor" stroke-width="1.5"/><path d="M8 6v4M8 11.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        Error Aggregation
      </router-link>
      <router-link to="/heatmap" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="14" height="14" rx="2" stroke="currentColor" stroke-width="1.5"/><rect x="3" y="3" width="4" height="4" fill="currentColor" opacity="0.3"/><rect x="9" y="3" width="4" height="4" fill="currentColor" opacity="0.6"/></svg>
        Health Heatmap
      </router-link>
      <router-link to="/compare" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M4 2v12M12 2v12M1 8h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
        DUT Comparison
      </router-link>
      <router-link to="/dependencies" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><circle cx="4" cy="4" r="2" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="12" r="2" stroke="currentColor" stroke-width="1.5"/><path d="M6 6l4 4" stroke="currentColor" stroke-width="1.5"/></svg>
        Dependencies
      </router-link>
      <router-link to="/coredumps" class="qa-link">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M3 2h10v12H3V2zM5 5h6M5 8h6M5 11h3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg>
        BMC Core Dump Handoff
      </router-link>
    </div>

    <details class="qa-runtime-logs">
      <summary class="qa-section-label">Runtime Logs ({{ runtimeLogFiles.length }})</summary>
      <div class="qa-runtime-logs__groups">
        <template v-if="runtimeLogFiles.length > 0">
          <div v-for="group in groupedRuntimeLogs" :key="group.dutId" class="qa-runtime-logs__group">
            <div v-if="group.dutId" style="font-size: 0.6875rem; color: var(--nv-text-tertiary); margin: 6px 0 2px; text-transform: uppercase; letter-spacing: 0.04em;">
              {{ group.dutId }}
            </div>
            <router-link
              v-for="file in group.files"
              :key="file.path"
              :to="`/file/${encodeURIComponent(file.path)}`"
              class="qa-file-link"
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 1h5l3 3v7H2V1z" stroke="currentColor" stroke-width="1"/></svg>
              {{ file.label }}
            </router-link>
          </div>
        </template>
        <span v-else style="font-size: 0.75rem; color: var(--nv-text-tertiary);">No runtime logs found</span>
      </div>
    </details>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useManifestStore } from '@/stores/manifest'

const manifestStore = useManifestStore()

const RUNTIME_LOG_NAMES: Record<string, string> = {
  '.nvdebug_stdout.log': 'Runtime Output Log',
  'nvdebug_runtime_output.txt': 'Runtime Output Log',
  '.log_signature.txt': 'Log Signature',
  'log_signature.txt': 'Log Signature',
  'config.json': 'Tool Configuration',
  'dut_config.json': 'DUT Configuration',
  'nvdebug_runtime_output_structured.txt': 'Structured Runtime Output',
  'Execution_Summary_Report.txt': 'Execution Summary Report',
  'collection_status_summary.txt': 'Collection Status Summary',
}

interface RuntimeLogEntry {
  path: string
  label: string
  dutId: string
}

const runtimeLogFiles = computed(() => {
  const results: RuntimeLogEntry[] = []
  const seen = new Set<string>()
  for (const file of manifestStore.fileIndex) {
    const parts = file.path.split('/')
    const name = parts[parts.length - 1]
    const label = RUNTIME_LOG_NAMES[name]
    if (!label) continue

    if (parts.length <= 1) {
      const key = `root:${label}`
      if (!seen.has(key)) {
        seen.add(key)
        results.push({ path: file.path, label, dutId: '' })
      }
    } else if (parts.length === 2) {
      const dutId = parts[0]
      const key = `${dutId}:${label}`
      if (!seen.has(key)) {
        seen.add(key)
        results.push({ path: file.path, label, dutId })
      }
    }
  }
  return results
})

const groupedRuntimeLogs = computed(() => {
  const groups = new Map<string, RuntimeLogEntry[]>()
  for (const f of runtimeLogFiles.value) {
    const key = f.dutId
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key)!.push(f)
  }
  return Array.from(groups.entries()).map(([dutId, files]) => ({ dutId, files }))
})
</script>

<style scoped>
.qa-tools {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 210px), 1fr));
  gap: 8px;
  margin-bottom: 12px;
}
.qa-runtime-logs {
  border-top: 1px solid var(--nv-glass-border);
  padding-top: 12px;
}
.qa-runtime-logs summary { cursor: pointer; }
.qa-runtime-logs__groups {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
  align-items: start;
  gap: 12px;
  max-height: 240px;
  overflow-y: auto;
}
.qa-runtime-logs__group { min-width: 0; overflow-wrap: anywhere; }
.qa-file-link svg { flex-shrink: 0; }
.qa-link {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  font-size: var(--nv-text-sm);
  color: var(--nv-text-secondary);
  text-decoration: none;
  border-radius: var(--nv-radius-md);
  transition: all var(--nv-duration-fast) var(--nv-ease);
}
.qa-link:hover {
  color: var(--nv-accent);
  background: var(--nv-accent-subtle);
}

.qa-section-label {
  font-size: 0.6875rem;
  font-weight: 600;
  color: var(--nv-text-tertiary);
  margin: 0 0 8px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.qa-file-link {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 8px;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  text-decoration: none;
  border-radius: var(--nv-radius-sm);
  transition: all var(--nv-duration-fast) var(--nv-ease);
}
.qa-file-link:hover {
  color: var(--nv-accent);
  background: var(--nv-accent-subtle);
}
</style>
