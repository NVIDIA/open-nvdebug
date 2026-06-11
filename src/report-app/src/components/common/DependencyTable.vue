<template>
  <div class="dep-tbl-viewport nv-table-viewport" style="max-height: 500px;">
    <table class="nv-table">
      <thead>
        <tr>
          <th>Collector</th>
          <th>Dependency</th>
          <th>Status</th>
          <th>Required</th>
          <th style="min-width: 180px;">Message</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="coll in collectors" :key="coll.collector_id">
          <tr v-for="(dep, i) in normalizeDeps(coll.dependencies)" :key="`${coll.collector_id}-${i}`">
            <td v-if="i === 0" :rowspan="Math.max(1, normalizeDeps(coll.dependencies).length)" class="dep-tbl__collector">
              <strong>{{ coll.collector_id }}</strong>
              <span v-if="coll.name" class="dep-tbl__collector-name">{{ coll.name }}</span>
            </td>
            <td class="dep-tbl__dep-name">{{ dep.name }}</td>
            <td>
              <span :class="['dep-tbl__status', `dep-tbl__status--${dep.status}`]">
                <span class="dep-tbl__status-icon">{{ statusIcon(dep.status) }}</span>
                {{ statusLabel(dep.status) }}
              </span>
            </td>
            <td>
              <span :class="['dep-tbl__required', dep.required ? 'dep-tbl__required--yes' : 'dep-tbl__required--no']">
                {{ dep.required ? 'Required' : 'Optional' }}
              </span>
            </td>
            <td class="dep-tbl__message">{{ dep.message || '\u2014' }}</td>
          </tr>
          <tr v-if="normalizeDeps(coll.dependencies).length === 0" :key="`${coll.collector_id}-empty`">
            <td class="dep-tbl__collector">
              <strong>{{ coll.collector_id }}</strong>
              <span v-if="coll.name" class="dep-tbl__collector-name">{{ coll.name }}</span>
            </td>
            <td colspan="4" style="color: var(--nv-text-tertiary); font-size: 0.75rem;">No dependencies</td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import type { DependencyEntry } from '@/types/manifest'

defineProps<{
  collectors: Array<{
    collector_id: string
    name: string
    dependencies: (DependencyEntry | string)[]
  }>
}>()

interface NormalizedDep {
  name: string
  type: string
  status: string
  message: string
  required: boolean
}

function normalizeDeps(deps: (DependencyEntry | string)[]): NormalizedDep[] {
  if (!Array.isArray(deps)) return []
  return deps.map(d => {
    if (typeof d === 'string') {
      return { name: d, type: 'unknown', status: 'unknown', message: '', required: true }
    }
    return {
      name: d.name ?? 'unknown',
      type: d.type ?? 'unknown',
      status: d.status ?? 'unknown',
      message: d.message ?? '',
      required: d.required ?? true,
    }
  })
}

function statusIcon(status: string): string {
  const s = status.toLowerCase()
  if (s === 'passed') return '\u2713'
  if (s === 'failed') return '\u2717'
  if (s === 'skipped') return '\u2014'
  return '?'
}

function statusLabel(status: string): string {
  const s = status.toLowerCase()
  if (s === 'passed') return 'Passed'
  if (s === 'failed') return 'Failed'
  if (s === 'skipped') return 'Skipped'
  if (s === 'not_applicable') return 'N/A'
  return status || 'Unknown'
}
</script>

<style scoped>
.dep-tbl__collector {
  vertical-align: top;
  font-size: 0.8125rem;
  white-space: nowrap;
}
.dep-tbl__collector-name {
  display: block;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  font-weight: 400;
  margin-top: 2px;
}
.dep-tbl__dep-name {
  font-size: 0.8125rem;
  font-weight: 500;
}
.dep-tbl__status {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 10px;
}
.dep-tbl__status-icon {
  font-size: 0.8125rem;
}
.dep-tbl__status--passed {
  color: var(--nv-success);
  background: var(--nv-success-muted);
}
.dep-tbl__status--failed {
  color: var(--nv-error);
  background: var(--nv-error-muted);
}
.dep-tbl__status--skipped {
  color: var(--nv-text-tertiary);
  background: var(--nv-glass-bg-light);
}
.dep-tbl__status--unknown {
  color: var(--nv-text-tertiary);
  background: var(--nv-glass-bg-light);
}
.dep-tbl__required {
  font-size: 0.6875rem;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 8px;
}
.dep-tbl__required--yes {
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-light);
  border: 1px solid var(--nv-glass-border);
}
.dep-tbl__required--no {
  color: var(--nv-text-tertiary);
  background: transparent;
  border: 1px solid var(--nv-glass-border);
}
.dep-tbl__message {
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  max-width: 300px;
  word-break: break-word;
  line-height: 1.4;
}
</style>
