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
  <div class="esv" :style="{ height }">
    <div class="esv__toolbar">
      <div>
        <strong>Execution Summary</strong>
        <span v-if="document.valid" class="esv__count">{{ document.rows.length }} collectors</span>
      </div>
      <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="showRaw = !showRaw">
        {{ showRaw ? 'Structured view' : 'Raw text' }}
      </button>
    </div>

    <pre v-if="showRaw || !document.valid" class="esv__raw">{{ rawPreview }}</pre>

    <div v-else class="esv__table-wrap">
      <table class="nv-table esv__table">
        <thead>
          <tr>
            <th>Collector</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Reason</th>
            <th>Output paths</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, index) in document.rows" :key="`${row.collectorId}:${row.collectionName}:${index}`">
            <td class="esv__collector">
              <strong>{{ row.collectionName || 'Unknown' }}</strong>
              <span>{{ row.collectorId || 'N/A' }}</span>
            </td>
            <td>
              <StatusBadge :status="row.status || 'unknown'" />
              <div v-if="row.failureCategory" class="esv__category">{{ row.failureCategory }}</div>
            </td>
            <td class="esv__duration">{{ formatDuration(row.durationSeconds) }}</td>
            <td class="esv__reason">
              <ReasonDisplay v-if="row.reason" :text="row.reason" :compact="true" />
              <span v-else class="esv__empty">&mdash;</span>
            </td>
            <td class="esv__paths">
              <details v-if="pathCount(row) > 0">
                <summary>{{ pathCount(row) }} {{ pathCount(row) === 1 ? 'path' : 'paths' }}</summary>
                <PathGroup label="Artifacts" :paths="row.artifactPaths" />
                <PathGroup label="Diagnostics" :paths="row.diagnosticPaths" />
                <PathGroup v-if="row.artifactPaths.length + row.diagnosticPaths.length === 0" label="Logs" :paths="row.logPaths" />
              </details>
              <span v-else class="esv__empty">&mdash;</span>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-if="document.totalExecutionTime" class="esv__total">{{ document.totalExecutionTime }}</div>
    </div>

    <div v-if="!document.valid" class="esv__warning">
      {{ document.error }} Showing the original text without reinterpretation.
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, ref, type PropType } from 'vue'
import ReasonDisplay from '@/components/common/ReasonDisplay.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { parseExecutionSummary, type ExecutionSummaryRow } from '@/utils/executionSummary'

const props = withDefaults(defineProps<{
  content: string
  height?: string
}>(), {
  height: '500px',
})

const showRaw = ref(false)
const document = computed(() => parseExecutionSummary(props.content))
const MAX_RAW_PREVIEW_CHARS = 1_000_000
const rawPreview = computed(() => props.content.length <= MAX_RAW_PREVIEW_CHARS
  ? props.content
  : `${props.content.slice(0, MAX_RAW_PREVIEW_CHARS)}\n\n[Preview truncated; download the original file to inspect the remainder.]`)

const PathGroup = defineComponent({
  props: {
    label: { type: String, required: true },
    paths: { type: Array as PropType<string[]>, required: true },
  },
  setup(pathProps) {
    return () => pathProps.paths.length
      ? h('section', { class: 'esv__path-group' }, [
          h('strong', pathProps.label),
          h('ul', pathProps.paths.map(path => h('li', { title: path }, path))),
        ])
      : null
  },
})

function formatDuration(value: string): string {
  if (!value) return '\u2014'
  const seconds = Number(value.replace(/s$/i, ''))
  return Number.isFinite(seconds) ? `${seconds.toFixed(1)}s` : value
}

function pathCount(row: ExecutionSummaryRow): number {
  const categorized = row.artifactPaths.length + row.diagnosticPaths.length
  return categorized || row.logPaths.length
}
</script>

<style scoped>
.esv {
  display: flex;
  flex-direction: column;
  min-height: 320px;
  overflow: hidden;
}
.esv__toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--nv-border);
}
.esv__count {
  margin-left: 8px;
  color: var(--nv-text-tertiary);
  font-size: 0.75rem;
  font-weight: 400;
}
.esv__table-wrap,
.esv__raw {
  flex: 1;
  min-height: 0;
  overflow: auto;
}
.esv__raw {
  margin: 0;
  padding: 12px;
  white-space: pre;
  font: 0.75rem/1.5 var(--nv-font-mono);
  color: var(--nv-text-primary);
  background: var(--nv-bg-elevated);
}
.esv__table {
  min-width: 960px;
  table-layout: fixed;
}
.esv__table th:nth-child(1) { width: 17%; }
.esv__table th:nth-child(2) { width: 10%; }
.esv__table th:nth-child(3) { width: 8%; }
.esv__table th:nth-child(4) { width: 42%; }
.esv__table th:nth-child(5) { width: 23%; }
.esv__table th {
  position: sticky;
  top: 0;
  z-index: 1;
  background: var(--nv-bg-elevated);
}
.esv__table td {
  vertical-align: top;
  white-space: normal;
}
.esv__collector strong,
.esv__collector span {
  display: block;
  overflow-wrap: anywhere;
}
.esv__collector span,
.esv__category,
.esv__empty {
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
}
.esv__duration {
  white-space: nowrap !important;
  font-family: var(--nv-font-mono);
}
.esv__reason {
  overflow-wrap: anywhere;
}
.esv__paths summary {
  color: var(--nv-accent);
  cursor: pointer;
  font-size: 0.75rem;
  font-weight: 600;
}
.esv__path-group {
  margin-top: 8px;
}
.esv__path-group strong {
  color: var(--nv-text-secondary);
  font-size: 0.6875rem;
}
.esv__path-group ul {
  margin: 4px 0 0;
  padding-left: 16px;
}
.esv__path-group li {
  margin: 3px 0;
  overflow-wrap: anywhere;
  font: 0.6875rem/1.4 var(--nv-font-mono);
}
.esv__total {
  padding: 8px 12px;
  color: var(--nv-text-secondary);
  border-top: 1px solid var(--nv-border);
  font: 0.75rem var(--nv-font-mono);
}
.esv__warning {
  padding: 8px 12px;
  color: var(--nv-warning);
  border-top: 1px solid var(--nv-border);
  font-size: 0.75rem;
}
</style>
