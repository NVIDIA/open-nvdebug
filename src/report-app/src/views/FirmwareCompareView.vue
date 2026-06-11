<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar">
      <AnalysisNav />
      <div style="border-top: 1px solid var(--nv-glass-border); margin: 6px 0;"></div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 6px 12px; margin: 0; font-size: 0.5625rem;">Filters</h4>
      <div style="padding: 8px 12px;">
        <input
          v-model="componentSearch"
          type="text"
          placeholder="Search components..."
          class="nv-input"
          style="width: 100%; font-size: 0.6875rem; padding: 4px 8px; margin-bottom: 8px;"
        />
        <label style="display: flex; align-items: center; gap: 6px; font-size: 0.6875rem; color: var(--nv-text-secondary); cursor: pointer; margin-bottom: 8px;">
          <input v-model="showOnlyMismatches" type="checkbox" />
          Show only mismatches
        </label>
      </div>

      <h4 class="nv-sidebar__section-title nv-glass--accent" style="padding: 6px 12px; margin: 0; font-size: 0.5625rem;">DUTs</h4>
      <div style="padding: 4px 0; max-height: 240px; overflow-y: auto;">
        <a
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': selectedDuts.length === 0 }"
          style="font-size: 0.6875rem; cursor: pointer;"
          @click="selectedDuts = []"
        >All DUTs ({{ manifestStore.duts.length }})</a>
        <a
          v-for="d in manifestStore.duts"
          :key="d.id"
          class="nv-sidebar__link"
          :class="{ 'nv-sidebar__link--active': selectedDuts.includes(d.id) }"
          style="font-size: 0.6875rem; cursor: pointer;"
          @click="toggleDut(d.id)"
        >{{ d.id }}</a>
      </div>
    </div>

    <div class="nv-page" style="margin-left: 260px;">
      <PageLoader v-if="!manifestStore.loaded" message="Comparing firmware versions..." />
      <template v-else>
        <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Firmware Comparison' }]" />
        <h2 class="nv-page__title" style="margin: 12px 0 8px;">Firmware Comparison</h2>

        <!-- Summary -->
        <div v-if="mismatchSummary.length > 0" class="nv-glass" style="padding: 12px 16px; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; cursor: pointer;" @click="mismatchExpanded = !mismatchExpanded">
            <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary); transition: transform 0.2s;" :style="{ transform: mismatchExpanded ? 'rotate(90deg)' : '' }">&#9654;</span>
            <h3 class="nv-section-title" style="margin: 0; font-size: 0.8125rem;">
              Mismatches Detected
              <span style="font-size: 0.6875rem; font-weight: 500; color: var(--nv-warning); margin-left: 6px;">{{ mismatchSummary.length }}</span>
            </h3>
          </div>
          <template v-if="mismatchExpanded">
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <div v-for="m in visibleMismatches" :key="m.name" style="font-size: 0.75rem; display: flex; align-items: center; gap: 8px;">
                <span style="color: var(--nv-warning); font-weight: 600;">&#9888;</span>
                <span style="color: var(--nv-text-primary); font-weight: 600;">{{ m.name }}</span>
                <span style="color: var(--nv-text-tertiary);">{{ m.uniqueVersions }} unique versions across {{ m.dutCount }} DUTs</span>
              </div>
            </div>
            <a
              v-if="mismatchSummary.length > 3 && !showAllMismatches"
              style="display: inline-block; margin-top: 6px; font-size: 0.6875rem; color: var(--nv-accent); cursor: pointer;"
              @click.stop="showAllMismatches = true"
            >Show {{ mismatchSummary.length - 3 }} more...</a>
          </template>
        </div>
        <div v-else class="nv-glass" style="padding: 16px; text-align: center; border-radius: var(--nv-radius-lg); margin-bottom: 16px;">
          <p style="font-size: 0.8125rem; color: var(--nv-success); margin: 0; font-weight: 600;">All firmware versions are consistent across DUTs.</p>
        </div>

        <p style="font-size: 0.6875rem; color: var(--nv-text-tertiary); margin: 0 0 8px;">
          Showing {{ filteredFirmwareNames.length }} of {{ firmwareNames.length }} components across {{ filteredDuts.length }} DUTs
        </p>

        <div v-if="firmwareNames.length === 0" class="nv-glass" style="padding: 32px; text-align: center; border-radius: var(--nv-radius-lg);">
          <p style="color: var(--nv-text-secondary); font-size: 0.875rem; margin: 0;">No firmware data available in the manifest.</p>
        </div>

        <!-- Matrix -->
        <div v-else class="fc-wrapper">
          <table class="fc-table">
            <thead>
              <tr>
                <th class="fc-th fc-th--corner">Component</th>
                <th v-for="dut in filteredDuts" :key="dut.id" class="fc-th fc-th--dut">
                  <span class="fc-th__text">{{ dut.id }}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="name in filteredFirmwareNames" :key="name">
                <td class="fc-td fc-td--name">{{ name }}</td>
                <td
                  v-for="dut in filteredDuts"
                  :key="dut.id"
                  :class="['fc-cell', { 'fc-cell--mismatch': isMismatch(name, dut.id) }]"
                  :title="`${name} on ${dut.id}: ${getVersion(name, dut.id)}`"
                >
                  {{ getVersion(name, dut.id) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const manifestStore = useManifestStore()

const componentSearch = ref('')
const showOnlyMismatches = ref(false)
const selectedDuts = ref<string[]>([])
const mismatchExpanded = ref(false)
const showAllMismatches = ref(false)

function toggleDut(id: string) {
  const idx = selectedDuts.value.indexOf(id)
  if (idx >= 0) selectedDuts.value.splice(idx, 1)
  else selectedDuts.value.push(id)
}

const filteredDuts = computed(() =>
  selectedDuts.value.length === 0
    ? manifestStore.duts
    : manifestStore.duts.filter(d => selectedDuts.value.includes(d.id))
)

const fwMap = computed(() => {
  const map = new Map<string, Map<string, string>>()
  for (const dut of manifestStore.duts) {
    for (const fw of dut.system_info?.firmware ?? []) {
      const key = fw.name || fw.id
      if (!map.has(key)) map.set(key, new Map())
      map.get(key)!.set(dut.id, fw.version)
    }
  }
  return map
})

const firmwareNames = computed(() => [...fwMap.value.keys()].sort())

const modeVersions = computed(() => {
  const modes = new Map<string, string>()
  for (const [name, dutVersions] of fwMap.value) {
    const counts = new Map<string, number>()
    for (const v of dutVersions.values()) {
      counts.set(v, (counts.get(v) ?? 0) + 1)
    }
    let modeVer = ''
    let modeCount = 0
    for (const [v, c] of counts) {
      if (c > modeCount) { modeVer = v; modeCount = c }
    }
    modes.set(name, modeVer)
  }
  return modes
})

const mismatchSet = computed(() => {
  const set = new Set<string>()
  for (const [name, dutVersions] of fwMap.value) {
    if (new Set(dutVersions.values()).size > 1) set.add(name)
  }
  return set
})

const mismatchSummary = computed(() => {
  const results: { name: string; uniqueVersions: number; dutCount: number }[] = []
  for (const [name, dutVersions] of fwMap.value) {
    const unique = new Set(dutVersions.values())
    if (unique.size > 1) {
      results.push({ name, uniqueVersions: unique.size, dutCount: dutVersions.size })
    }
  }
  return results
})

const visibleMismatches = computed(() =>
  showAllMismatches.value ? mismatchSummary.value : mismatchSummary.value.slice(0, 3)
)

const filteredFirmwareNames = computed(() => {
  let names = firmwareNames.value
  if (componentSearch.value) {
    const q = componentSearch.value.toLowerCase()
    names = names.filter(n => n.toLowerCase().includes(q))
  }
  if (showOnlyMismatches.value) {
    names = names.filter(n => mismatchSet.value.has(n))
  }
  return names
})

function getVersion(name: string, dutId: string): string {
  return fwMap.value.get(name)?.get(dutId) ?? '—'
}

function isMismatch(name: string, dutId: string): boolean {
  const ver = fwMap.value.get(name)?.get(dutId)
  if (!ver) return false
  return ver !== modeVersions.value.get(name)
}
</script>

<style scoped>
.fc-wrapper {
  overflow: auto;
  max-height: calc(100vh - 300px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
}
.fc-table {
  border-collapse: collapse;
  font-size: 0.6875rem;
  width: 100%;
}
.fc-th {
  position: sticky;
  top: 0;
  background: var(--nv-surface-primary);
  z-index: 2;
  padding: 6px 8px;
  border-bottom: 1px solid var(--nv-glass-border);
  font-weight: 600;
  color: var(--nv-text-secondary);
  white-space: nowrap;
}
.fc-th--corner {
  position: sticky;
  left: 0;
  z-index: 3;
  min-width: 140px;
  text-align: left;
}
.fc-th--dut {
  text-align: center;
  min-width: 80px;
}
.fc-td--name {
  position: sticky;
  left: 0;
  background: var(--nv-surface-primary);
  z-index: 1;
  padding: 6px 8px;
  font-weight: 600;
  color: var(--nv-text-primary);
  white-space: nowrap;
  border-right: 1px solid var(--nv-glass-border);
}
.fc-cell {
  padding: 4px 6px;
  text-align: center;
  font-family: var(--nv-font-mono);
  color: var(--nv-text-secondary);
  border-bottom: 1px solid var(--nv-glass-border);
}
.fc-cell--mismatch {
  background: var(--nv-warning-muted);
  color: var(--nv-warning);
  font-weight: 700;
}
</style>
