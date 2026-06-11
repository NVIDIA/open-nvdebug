<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Run Comparison' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 20px;">Run Comparison</h2>

    <!-- Load second manifest -->
    <div v-if="!comparisonManifest" class="nv-glass--accent" style="padding: 32px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h3 style="color: var(--nv-text-primary); margin: 0 0 8px; font-size: 1rem;">Compare Two NVDebug Runs</h3>
        <p style="color: var(--nv-text-secondary); margin: 0; font-size: 0.8125rem; max-width: 520px; margin-inline: auto;">
          Load a second NVDebug report folder to compare collector statuses, execution times, and file outputs against the currently loaded run. This helps identify regressions, improvements, and new/removed collectors between runs.
        </p>
      </div>

      <div style="text-align: center; margin-bottom: 20px;">
        <label class="nv-btn nv-btn--primary nv-btn--lg">
          Select Report Folder
          <input type="file" webkitdirectory style="display: none;" @change="onDirectorySelected" />
        </label>
      </div>
      <p v-if="loadError" style="color: var(--nv-error); margin-top: 12px; font-size: 0.8125rem; text-align: center;">{{ loadError }}</p>
      <p v-if="schemaWarning" style="color: var(--nv-warning); margin-top: 8px; font-size: 0.75rem; text-align: center;">{{ schemaWarning }}</p>

      <div class="nv-glass" style="padding: 16px; border-radius: var(--nv-radius-md); margin-top: 16px;">
        <h4 style="margin: 0 0 8px; font-size: 0.8125rem; color: var(--nv-text-primary); cursor: pointer;" @click="showHelpExpanded = !showHelpExpanded">
          <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary); transition: transform 0.2s; display: inline-block;" :style="{ transform: showHelpExpanded ? 'rotate(90deg)' : '' }">&#9654;</span>
          What is Run Comparison?
        </h4>
        <div v-if="showHelpExpanded" style="font-size: 0.75rem; color: var(--nv-text-secondary); display: flex; flex-direction: column; gap: 8px;">
          <p style="margin: 0;">Run Comparison lets you diff two <code style="font-family: var(--nv-font-mono); background: var(--nv-glass-bg-light); padding: 1px 4px; border-radius: 3px;">open-nvdebug</code> report folders. Point to a second report&rsquo;s folder (the one containing <code style="font-family: var(--nv-font-mono); background: var(--nv-glass-bg-light); padding: 1px 4px; border-radius: 3px;">manifest.json</code>) and the tool will compare:</p>
          <ul style="margin: 0; padding-left: 18px;">
            <li><strong>Collector statuses</strong> &mdash; did a collector switch from success to error (regression) or the reverse (improvement)?</li>
            <li><strong>Execution times</strong> &mdash; significant duration changes are flagged.</li>
            <li><strong>File counts</strong> &mdash; changes in the number of output files per collector.</li>
          </ul>
          <div style="padding: 8px 12px; background: var(--nv-glass-bg-light); border-radius: 6px; border-left: 3px solid var(--nv-accent);">
            <strong style="color: var(--nv-text-primary);">Compatibility:</strong> Works best with NVDebug manifest schema v1.0+. Older reports may have partial data, and some fields may appear as &ldquo;N/A&rdquo; if the schema differs. Both reports should target the same baseboard for meaningful comparison.
          </div>
        </div>
      </div>
    </div>

    <!-- Comparison content -->
    <template v-else>
      <div class="nv-glass--subtle" style="display: flex; gap: 12px; margin-bottom: 16px; padding: 10px 16px; border-radius: 8px; align-items: center; flex-wrap: wrap;">
        <span class="nv-badge nv-badge--accent">Run A: {{ manifestStore.generatedAt }}</span>
        <span style="color: var(--nv-text-secondary);">vs</span>
        <span class="nv-badge nv-badge--info">Run B: {{ comparisonManifest.generated_at }}</span>
        <span style="flex: 1;" />
        <button @click="comparisonManifest = null; schemaWarning = ''" class="nv-btn nv-btn--sm">Clear</button>
      </div>

      <div v-if="schemaWarning" class="nv-glass" style="padding: 10px 16px; margin-bottom: 12px; border-radius: var(--nv-radius-md); border-left: 3px solid var(--nv-warning); font-size: 0.75rem; color: var(--nv-warning);">
        &#9888; {{ schemaWarning }}
      </div>

      <!-- Summary stat cards -->
      <div class="cmp-stats">
        <div class="cmp-stat cmp-stat--regressions">
          <div class="cmp-stat__value">{{ regressionCount }}</div>
          <div class="cmp-stat__label">Regressions</div>
        </div>
        <div class="cmp-stat cmp-stat--improvements">
          <div class="cmp-stat__value">{{ improvementCount }}</div>
          <div class="cmp-stat__label">Improvements</div>
        </div>
        <div class="cmp-stat cmp-stat--changed">
          <div class="cmp-stat__value">{{ changedCount }}</div>
          <div class="cmp-stat__label">Changed</div>
        </div>
        <div class="cmp-stat cmp-stat--new">
          <div class="cmp-stat__value">{{ newCount }}</div>
          <div class="cmp-stat__label">New in B</div>
        </div>
        <div class="cmp-stat cmp-stat--removed">
          <div class="cmp-stat__value">{{ removedCount }}</div>
          <div class="cmp-stat__label">Removed</div>
        </div>
      </div>

      <!-- Filter: show only changes -->
      <div style="display: flex; gap: 12px; margin-bottom: 12px; align-items: center;">
        <label style="font-size: 0.75rem; display: flex; align-items: center; gap: 4px; cursor: pointer; color: var(--nv-text-secondary);">
          <input type="checkbox" v-model="showOnlyChanges" style="accent-color: var(--nv-accent);" />
          Show only changes
        </label>
      </div>

      <!-- Status Delta Table -->
      <div class="nv-card" style="margin-bottom: 16px;">
        <h3 class="nv-section-subtitle">Collector Status &amp; Duration Comparison</h3>
        <div class="nv-table-viewport">
          <DataTable :columns="deltaColumns" :data="tableData" :searchable="true">
            <template #cell-statusA="{ value }">
              <StatusBadge v-if="value" :status="value" />
              <span v-else class="cmp-na">&mdash;</span>
            </template>
            <template #cell-statusB="{ value }">
              <StatusBadge v-if="value" :status="value" />
              <span v-else class="cmp-na">&mdash;</span>
            </template>
            <template #cell-durationA="{ value }">
              <span v-if="value != null">{{ value.toFixed(1) }}s</span>
              <span v-else class="cmp-na">&mdash;</span>
            </template>
            <template #cell-durationB="{ value }">
              <span v-if="value != null">{{ value.toFixed(1) }}s</span>
              <span v-else class="cmp-na">&mdash;</span>
            </template>
            <template #cell-delta="{ row }">
              <span v-if="row.delta == null" class="cmp-na">&mdash;</span>
              <span v-else-if="row.delta > 0" class="cmp-delta cmp-delta--slower">+{{ row.delta.toFixed(1) }}s</span>
              <span v-else-if="row.delta < 0" class="cmp-delta cmp-delta--faster">{{ row.delta.toFixed(1) }}s</span>
              <span v-else class="cmp-na">0s</span>
            </template>
            <template #cell-verdict="{ row }">
              <span v-if="row.verdict === 'regression'" class="cmp-verdict cmp-verdict--regression">Regression</span>
              <span v-else-if="row.verdict === 'improvement'" class="cmp-verdict cmp-verdict--improvement">Improvement</span>
              <span v-else-if="row.verdict === 'new'" class="cmp-verdict cmp-verdict--new">New</span>
              <span v-else-if="row.verdict === 'removed'" class="cmp-verdict cmp-verdict--removed">Removed</span>
              <span v-else class="cmp-na">Same</span>
            </template>
          </DataTable>
        </div>
      </div>
    </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import type { Manifest } from '@/types/manifest'
import { naturalCompare } from '@/utils/naturalSort'

const manifestStore = useManifestStore()
const comparisonManifest = ref<Manifest | null>(null)
const loadError = ref('')
const schemaWarning = ref('')
const showOnlyChanges = ref(false)
const showHelpExpanded = ref(false)

interface Column { key: string; label: string }
const deltaColumns: Column[] = [
  { key: 'dut', label: 'DUT' },
  { key: 'collector', label: 'Collector' },
  { key: 'statusA', label: 'Run A Status' },
  { key: 'statusB', label: 'Run B Status' },
  { key: 'durationA', label: 'Run A Time' },
  { key: 'durationB', label: 'Run B Time' },
  { key: 'delta', label: 'Delta' },
  { key: 'verdict', label: 'Verdict' },
]

const STATUS_RANK: Record<string, number> = {
  success: 0, partial: 1, skipped: 2, not_ran: 3, error: 4, failed: 4,
}

function buildStatusMap(manifest: Manifest): Map<string, { status: string; duration: number | null }> {
  const map = new Map<string, { status: string; duration: number | null }>()
  for (const dut of manifest.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        map.set(`${dut.id}::${c.id}`, {
          status: c.status,
          duration: c.execution_time ?? null,
        })
      }
    }
  }
  return map
}

function computeVerdict(statusA: string | null, statusB: string | null): 'regression' | 'improvement' | 'new' | 'removed' | 'same' {
  if (!statusA && statusB) return 'new'
  if (statusA && !statusB) return 'removed'
  if (!statusA || !statusB) return 'same'
  const rA = STATUS_RANK[statusA] ?? 3
  const rB = STATUS_RANK[statusB] ?? 3
  if (rB > rA) return 'regression'
  if (rB < rA) return 'improvement'
  return 'same'
}

const statusDeltas = computed(() => {
  if (!comparisonManifest.value || !manifestStore.manifest) return []
  const mapA = buildStatusMap(manifestStore.manifest)
  const mapB = buildStatusMap(comparisonManifest.value)
  const allKeys = new Set([...mapA.keys(), ...mapB.keys()])
  const deltas: any[] = []

  for (const key of [...allKeys].sort(naturalCompare)) {
    const [dut, collector] = key.split('::')
    const a = mapA.get(key)
    const b = mapB.get(key)
    const statusA = a?.status ?? null
    const statusB = b?.status ?? null
    const durationA = a?.duration ?? null
    const durationB = b?.duration ?? null
    const delta = (durationA != null && durationB != null) ? (durationB - durationA) : null
    const verdict = computeVerdict(statusA, statusB)

    deltas.push({ dut, collector, statusA, statusB, durationA, durationB, delta, verdict })
  }
  return deltas
})

const tableData = computed(() => {
  if (!showOnlyChanges.value) return statusDeltas.value
  return statusDeltas.value.filter(d => d.verdict !== 'same')
})

const changedCount = computed(() => statusDeltas.value.filter(d => d.statusA !== d.statusB && d.statusA && d.statusB).length)
const regressionCount = computed(() => statusDeltas.value.filter(d => d.verdict === 'regression').length)
const improvementCount = computed(() => statusDeltas.value.filter(d => d.verdict === 'improvement').length)
const newCount = computed(() => statusDeltas.value.filter(d => d.verdict === 'new').length)
const removedCount = computed(() => statusDeltas.value.filter(d => d.verdict === 'removed').length)

function checkSchemaCompat(loaded: Manifest) {
  schemaWarning.value = ''
  const currentSchema = manifestStore.manifest?.schema_version
  const loadedSchema = loaded.schema_version
  if (currentSchema && loadedSchema && currentSchema !== loadedSchema) {
    schemaWarning.value = `Schema version mismatch: current report is v${currentSchema}, loaded report is v${loadedSchema}. Some fields may not align.`
  } else if (!loadedSchema) {
    schemaWarning.value = 'The loaded report has no schema version. It may be from an older NVDebug release. Some comparisons may be incomplete.'
  }
}

async function onDirectorySelected(event: Event) {
  const input = event.target as HTMLInputElement
  if (!input.files || input.files.length === 0) return
  loadError.value = ''
  schemaWarning.value = ''

  for (let i = 0; i < input.files.length; i++) {
    const file = input.files[i]
    const relPath = (file as any).webkitRelativePath as string
    if (relPath.endsWith('manifest.json') || (relPath.includes('reports/') && relPath.endsWith('manifest.json'))) {
      try {
        const text = await file.text()
        const parsed = JSON.parse(text) as Manifest
        comparisonManifest.value = parsed
        checkSchemaCompat(parsed)
        return
      } catch {
        loadError.value = 'Failed to parse manifest.json'
        return
      }
    }
  }

  for (let i = 0; i < input.files.length; i++) {
    const file = input.files[i]
    const relPath = (file as any).webkitRelativePath as string
    if (relPath.endsWith('index.html') && relPath.includes('reports/')) {
      try {
        const html = await file.text()
        const match = html.match(/window\.__MANIFEST__\s*=\s*({[\s\S]*?});?\s*<\/script>/)
        if (match) {
          const parsed = JSON.parse(match[1]) as Manifest
          comparisonManifest.value = parsed
          checkSchemaCompat(parsed)
          return
        }
      } catch { /* ignore */ }
    }
  }

  loadError.value = 'Could not find manifest.json or embedded manifest in the selected directory.'
}
</script>

<style scoped>
.cmp-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.cmp-stat {
  padding: 12px 16px;
  border-radius: var(--nv-radius-lg);
  background: var(--nv-glass-bg-light);
  backdrop-filter: blur(8px);
  border: 1px solid var(--nv-glass-border);
  text-align: center;
}
.cmp-stat__value {
  font-size: 1.75rem;
  font-weight: 700;
  line-height: 1.2;
}
.cmp-stat__label {
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-top: 2px;
}
.cmp-stat--regressions .cmp-stat__value { color: var(--nv-error); }
.cmp-stat--improvements .cmp-stat__value { color: var(--nv-success); }
.cmp-stat--changed .cmp-stat__value { color: var(--nv-warning); }
.cmp-stat--new .cmp-stat__value { color: var(--nv-accent); }
.cmp-stat--removed .cmp-stat__value { color: var(--nv-text-tertiary); }

.cmp-na { color: var(--nv-text-tertiary); }

.cmp-delta {
  font-family: var(--nv-font-mono, monospace);
  font-size: 0.75rem;
  font-weight: 600;
}
.cmp-delta--slower { color: var(--nv-error); }
.cmp-delta--faster { color: var(--nv-success); }

.cmp-verdict {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 0.6875rem;
  font-weight: 600;
}
.cmp-verdict--regression { background: rgba(var(--nv-error-rgb, 239, 68, 68), 0.15); color: var(--nv-error); }
.cmp-verdict--improvement { background: rgba(var(--nv-success-rgb, 34, 197, 94), 0.15); color: var(--nv-success); }
.cmp-verdict--new { background: var(--nv-accent-muted); color: var(--nv-accent); }
.cmp-verdict--removed { background: var(--nv-glass-bg-light); color: var(--nv-text-tertiary); }
</style>
