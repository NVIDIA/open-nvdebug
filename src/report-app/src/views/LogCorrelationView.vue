<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page corr-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'Log Correlation' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 12px;">Log Correlation — Play-by-Play</h2>
    <p class="corr-subtitle">Chronological interleave of log events across files. See what happened, when.</p>

    <!-- DUT Scope Selector + Service Filter + File Picker -->
    <div class="nv-card corr-controls">
      <div class="corr-controls__top">
        <div class="corr-controls__scope">
          <label class="corr-controls__label">DUT Scope</label>
          <select v-model="dutScope" class="nv-select" style="min-width: 180px;">
            <option value="all">All DUTs ({{ manifestStore.duts.length }})</option>
            <option v-for="d in manifestStore.duts" :key="d.id" :value="d.id">{{ d.id }}</option>
          </select>
        </div>

        <!-- Service filter pills -->
        <div class="corr-controls__scope">
          <label class="corr-controls__label">Service</label>
          <DutPillSelector
            v-model="activeServiceFilters"
            :options="serviceFilterOptions"
            :multiple="true"
          />
        </div>

        <div class="corr-controls__actions">
          <span class="corr-controls__file-count">
            {{ checkedFiles.length }}/{{ MAX_FILES }} files selected
          </span>
          <button
            @click="correlateAll"
            :disabled="checkedFiles.length === 0 || loading"
            class="nv-btn nv-btn--primary nv-btn--sm"
          >
            Correlate
          </button>
        </div>
      </div>

      <!-- Grouped file picker -->
      <div class="corr-file-picker">
        <div v-for="group in fileGroups" :key="group.dutId" class="corr-file-group">
          <div class="corr-file-group__header" @click="toggleGroupExpand(group.dutId)">
            <span class="corr-file-group__chevron">{{ expandedGroups.has(group.dutId) ? '\u25BC' : '\u25B6' }}</span>
            <span class="corr-file-group__dut">{{ group.dutId }}</span>
            <span class="corr-file-group__count">{{ group.files.length }} files</span>
            <span style="flex: 1;" />
            <button class="nv-btn nv-btn--ghost nv-btn--sm" style="font-size: 0.625rem;" @click.stop="toggleGroupAll(group)">
              {{ isGroupFullyChecked(group) ? 'Deselect all' : 'Select all' }}
            </button>
          </div>
          <div v-if="expandedGroups.has(group.dutId)" class="corr-file-group__files">
            <label
              v-for="f in group.files"
              :key="f.path"
              class="corr-file-item"
              :class="{ 'corr-file-item--disabled': !isFileChecked(f.path) && checkedFiles.length >= MAX_FILES }"
            >
              <input
                type="checkbox"
                :checked="isFileChecked(f.path)"
                :disabled="!isFileChecked(f.path) && checkedFiles.length >= MAX_FILES"
                @change="toggleFile(f.path)"
              />
              <span class="corr-file-item__dot" :style="{ background: getFileColor(f.path) }" />
              <span class="corr-file-item__name" :title="f.path">{{ f.path.split('/').pop() }}</span>
              <span class="corr-file-item__meta">{{ f.collector_id }}</span>
              <span class="corr-file-item__size">{{ formatFileSize(f.size) }}</span>
              <span v-if="isRuntimeLog(f)" class="corr-file-item__badge">runtime</span>
            </label>
          </div>
        </div>
        <div v-if="fileGroups.length === 0" style="padding: 12px; font-size: 0.75rem; color: var(--nv-text-tertiary);">
          No text log files found for the selected DUT scope.
        </div>
      </div>
    </div>

    <!-- Processing Dialog -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="loading" class="nv-modal-overlay" style="z-index: 9999;">
          <div class="nv-modal nv-modal--sm" style="padding: 32px; text-align: center;">
            <svg width="40" height="31" viewBox="0 0 34 30" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M16.889 8.985V6.28c.262-.02.528-.033.798-.042 7.4-.232 12.255 6.359 12.255 6.359s-5.244 7.282-10.866 7.282a6.82 6.82 0 0 1-2.187-.35v-8.204c2.88.348 3.46 1.62 5.192 4.508l3.852-3.248s-2.812-3.688-7.552-3.688c-.515 0-1.008.036-1.492.088zm0-8.938V4.09c.265-.021.531-.038.798-.048 10.29-.346 16.995 8.44 16.995 8.44s-7.7 9.364-15.723 9.364c-.735 0-1.424-.068-2.07-.183v2.498c.553.07 1.126.112 1.724.112 7.465 0 12.864-3.812 18.092-8.325.867.694 4.416 2.383 5.145 3.123-4.971 4.16-16.555 7.515-23.123 7.515a18.89 18.89 0 0 1-1.838-.096V30h28.375V.047H16.89zm0 19.482v2.133c-6.905-1.23-8.822-8.408-8.822-8.408s3.316-3.674 8.822-4.269v2.34l-.011-.001c-2.89-.347-5.147 2.353-5.147 2.353s1.265 4.544 5.158 5.852zM4.625 12.943s4.092-6.04 12.264-6.663V4.088C7.838 4.815 0 12.48 0 12.48s4.439 12.833 16.889 14.008V24.16C7.753 23.011 4.625 12.943 4.625 12.943z" fill="#76B900"/>
            </svg>
            <div style="margin-top: 16px; font-size: 1rem; font-weight: 600; color: var(--nv-text-primary);">Processing Logs</div>
            <div style="margin-top: 8px; font-size: 0.75rem; color: var(--nv-text-secondary);">
              Loading file {{ loadProgress }} of {{ checkedFiles.length }}
            </div>
            <div v-if="currentFileName" style="margin-top: 4px; font-size: 0.6875rem; color: var(--nv-text-tertiary); font-family: var(--nv-font-mono);">
              {{ currentFileName }}
            </div>
            <!-- Progress bar -->
            <div style="margin-top: 16px; height: 6px; border-radius: 3px; background: var(--nv-bg-tertiary); overflow: hidden;">
              <div
                style="height: 100%; border-radius: 3px; background: var(--nv-accent); transition: width 0.2s ease;"
                :style="{ width: (checkedFiles.length ? (loadProgress / checkedFiles.length) * 100 : 0) + '%' }"
              />
            </div>
            <button class="nv-btn nv-btn--ghost nv-btn--sm" style="margin-top: 16px;" @click="cancelCorrelation">Cancel</button>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Results -->
    <template v-if="events.length > 0">
      <!-- Stats bar -->
      <div class="corr-stats nv-glass--subtle">
        <span>{{ events.length.toLocaleString() }} events correlated</span>
        <span>{{ checkedFiles.length }} files</span>
        <span>Time range: {{ formatTimeRange() }}</span>
        <span v-if="brushRange">Selected: {{ brushedEvents.length.toLocaleString() }} events</span>
      </div>

      <!-- Timeline panel -->
      <div class="corr-timeline-panel">
        <LogTimeline
          :events="timelineEvents"
          :sources="checkedFiles.map(f => f.split('/').pop() ?? f)"
          @brush-range="onBrushRange"
          @select-event="onSelectEvent"
          @level-filter="onLevelFilter"
        />
      </div>

      <!-- Category breakdown bar -->
      <div v-if="events.length > 0" class="corr-category-bar nv-glass--subtle">
        <span class="corr-category-bar__label">Categories:</span>
        <button
          v-for="cat in categoryBreakdown"
          :key="cat.category"
          :class="['corr-cat-chip', { 'corr-cat-chip--active': activeCategories.size === 0 || activeCategories.has(cat.category) }]"
          :style="{ '--cat-color': CATEGORY_COLORS[cat.category] }"
          @click="toggleCategory(cat.category)"
          :title="`${CATEGORY_LABELS[cat.category]}: ${cat.count} events (${cat.pct}%)`"
        >
          <span class="corr-cat-chip__dot" :style="{ background: CATEGORY_COLORS[cat.category] }" />
          {{ CATEGORY_LABELS[cat.category] }}
          <span class="corr-cat-chip__count">{{ cat.count }}</span>
        </button>
        <button v-if="activeCategories.size > 0" class="nv-btn nv-btn--ghost nv-btn--sm" style="font-size: 0.625rem; margin-left: 4px;" @click="activeCategories.clear()">Clear</button>
      </div>

      <!-- Event detail panel -->
      <Transition name="corr-detail">
        <div v-if="selectedEvent" class="corr-detail nv-glass--accent">
          <div class="corr-detail__header">
            <span class="corr-detail__title">Event Detail</span>
            <span style="flex: 1;" />
            <button class="nv-btn nv-btn--ghost nv-btn--sm" style="font-size: 0.625rem;" @click="scrollToEventInList" title="Scroll to this event in the list">Locate in list</button>
            <button class="nv-btn nv-btn--ghost nv-btn--sm" style="font-size: 0.625rem;" @click="navigateToFile(selectedEvent)" title="Open source file">Open file</button>
            <button class="nv-btn nv-btn--ghost nv-btn--sm" style="font-size: 0.625rem; padding: 2px 6px;" @click="selectedEvent = null" title="Close">&times;</button>
          </div>
          <div class="corr-detail__body">
            <div class="corr-detail__meta">
              <span class="corr-detail__badge" :style="{ color: getFileColor(selectedEvent.source) }">{{ selectedEvent.source.split('/').pop() }}</span>
              <span v-if="selectedEvent.level" :class="['corr-list__level', `corr-list__level--${selectedEvent.level?.toLowerCase()}`]" style="font-size: 0.6875rem;">{{ selectedEvent.level }}</span>
              <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">{{ formatTimestamp(selectedEvent.timestamp) }}</span>
              <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">Line #{{ selectedEvent.lineNumber }}</span>
              <span v-if="dutScope === 'all'" style="font-size: 0.6875rem; color: var(--nv-accent);">{{ getDutForFile(selectedEvent.source) }}</span>
            </div>
            <pre class="corr-detail__content">{{ selectedEvent.line }}</pre>
          </div>
        </div>
      </Transition>

      <!-- Event list panel -->
      <div class="corr-list-panel nv-card">
        <div class="corr-list__toolbar">
          <input v-model="searchFilter" type="text" placeholder="Search events..." class="nv-input" style="width: 200px;" />
          <div class="corr-list__level-pills">
            <button
              v-for="lv in LEVEL_OPTIONS"
              :key="lv.key"
              :class="['corr-lvl-pill', { 'corr-lvl-pill--active': !hiddenLevels.has(lv.key) }]"
              :style="{ '--lvl-color': lv.color }"
              @click="toggleListLevel(lv.key)"
            >{{ lv.label }}</button>
          </div>
          <span class="corr-list__count">{{ displayedEvents.length.toLocaleString() }} events</span>
        </div>
        <div ref="eventListRef" class="corr-list__events" @scroll="virtualScroll.onScroll">
          <div :style="{ height: virtualScroll.totalHeight.value + 'px', position: 'relative' }">
            <div :style="{ transform: `translateY(${virtualScroll.offsetY.value}px)` }">
              <div
                v-for="{ item: evt, index: i } in virtualScroll.visibleItems.value"
                :key="i"
                :class="['corr-list__row', { 'corr-list__row--highlight': highlightedIndex === i, 'corr-list__row--selected': selectedEvent === evt }]"
                :style="{ borderLeftColor: getFileColor(evt.source), height: EVENT_ROW_HEIGHT + 'px' }"
                @click="selectEventFromList(evt)"
                @dblclick="navigateToFile(evt)"
              >
                <span class="corr-list__ts">{{ formatTimestamp(evt.timestamp) }}</span>
                <span class="corr-list__dut" v-if="dutScope === 'all'">{{ getDutForFile(evt.source) }}</span>
                <span class="corr-list__src" :style="{ color: getFileColor(evt.source) }" :title="evt.source">
                  {{ evt.source.split('/').pop() }}
                </span>
                <span v-if="evt.level" :class="['corr-list__level', `corr-list__level--${evt.level?.toLowerCase()}`]">
                  {{ evt.level }}
                </span>
                <span class="corr-list__msg">{{ extractMessage(evt.line) }}</span>
                <span class="corr-list__line">#{{ evt.lineNumber }}</span>
              </div>
            </div>
          </div>
          <EmptyState
            v-if="displayedEvents.length === 0"
            icon="search"
            title="No events match"
            description="Adjust your search, level filter, or clear the time selection."
          />
        </div>
      </div>
    </template>

    <EmptyState
      v-else-if="!loading && correlationRan"
      icon="data"
      title="No timestamped events found"
      description="The selected files don't contain recognizable timestamp patterns. Try different log files."
    />
    <EmptyState
      v-else-if="!loading && checkedFiles.length > 0"
      icon="data"
      title="Ready to correlate"
      description="Click Correlate to interleave events from the selected files by timestamp."
    />
    <EmptyState
      v-else-if="!loading"
      icon="file"
      title="Select files to correlate"
      description="Choose log files from the file picker above to view their events on a shared timeline."
    />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { DataLoader } from '@/services/dataLoader'
import { correlateFiles, categoryFromCollectorId, type CorrelationEvent, type LogCategory, CATEGORY_COLORS, CATEGORY_LABELS } from '@/composables/useLogCorrelation'
import { useVirtualScroll } from '@/composables/useVirtualScroll'
import LogTimeline from '@/components/charts/LogTimeline.vue'
import type { TimelineEvent } from '@/components/charts/LogTimeline.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import EmptyState from '@/components/common/EmptyState.vue'
import DutPillSelector from '@/components/common/DutPillSelector.vue'
import type { PillOption } from '@/components/common/DutPillSelector.vue'

const MAX_FILES = 10
const EVENT_ROW_HEIGHT = 28

const LEVEL_OPTIONS = [
  { key: 'error', label: 'Error', color: 'var(--nv-error)' },
  { key: 'warning', label: 'Warning', color: 'var(--nv-warning)' },
  { key: 'info', label: 'Info', color: 'var(--nv-info)' },
  { key: 'debug', label: 'Debug', color: 'var(--nv-text-tertiary)' },
] as const

const router = useRouter()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()

const dutScope = ref('all')
const activeServiceFilters = ref<string[]>([])
const checkedPaths = reactive(new Set<string>())
const expandedGroups = reactive(new Set<string>())
const events = ref<CorrelationEvent[]>([])
const loading = ref(false)
const loadProgress = ref(0)
const currentFileName = ref('')
const cancelled = ref(false)
const correlationRan = ref(false)
const searchFilter = ref('')
const levelFilter = ref('')
const hiddenLevels = reactive(new Set<string>())
const activeCategories = reactive(new Set<LogCategory>())
const brushRange = ref<{ start: number; end: number } | null>(null)
const highlightedIndex = ref(-1)
const selectedEvent = ref<CorrelationEvent | null>(null)
const eventListRef = ref<HTMLElement>()
const containerHeight = ref(500)

const LOG_FILE_PATTERNS = /\.(log|txt|out|err|journal|json|csv|xml|yaml|yml|conf|cfg)$/i
const RUNTIME_LOG_PATTERNS = /runtime_log|nvdebug.*\.log|nvdebug_.*\.txt/i
const MAX_FILE_SIZE = 50_000_000

const SERVICE_TYPES = ['redfish', 'ssh', 'ipmi', 'host', 'bmc', 'health_check'] as const

const serviceFilterOptions = computed<PillOption[]>(() => {
  const serviceSet = new Set<string>()
  for (const f of scopedFiles.value) {
    if (f.collector_id) {
      const cat = categoryFromCollectorId(f.collector_id)
      if (cat !== 'general') serviceSet.add(cat)
    }
  }
  return SERVICE_TYPES
    .filter(s => serviceSet.has(s))
    .map(s => ({ id: s, label: CATEGORY_LABELS[s] }))
})

const SOURCE_COLORS = [
  '#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b', '#10b981',
  '#ef4444', '#ec4899', '#6366f1', '#14b8a6', '#f97316',
]

const fileColorMap = computed(() => {
  const map = new Map<string, string>()
  let idx = 0
  for (const path of checkedPaths) {
    map.set(path, SOURCE_COLORS[idx % SOURCE_COLORS.length])
    idx++
  }
  return map
})

function getFileColor(path: string): string {
  return fileColorMap.value.get(path) ?? 'var(--nv-text-tertiary)'
}

interface FileGroup {
  dutId: string
  files: Array<{ path: string; collector_id: string; size: number; type: string; dut_id: string }>
}

const scopedFiles = computed(() => {
  return manifestStore.fileIndex.filter(f => {
    if (f.type === 'binary') return false
    if (f.size > MAX_FILE_SIZE) return false
    if (!LOG_FILE_PATTERNS.test(f.path) && f.type !== 'log' && f.type !== 'text') return false
    if (dutScope.value !== 'all' && f.dut_id !== dutScope.value) return false
    return true
  })
})

const filteredFiles = computed(() => {
  if (activeServiceFilters.value.length === 0) return scopedFiles.value
  return scopedFiles.value.filter(f => {
    const cat = categoryFromCollectorId(f.collector_id)
    return activeServiceFilters.value.includes(cat) || cat === 'general'
  })
})

const fileGroups = computed<FileGroup[]>(() => {
  const groups = new Map<string, FileGroup>()
  for (const f of filteredFiles.value) {
    if (!groups.has(f.dut_id)) {
      groups.set(f.dut_id, { dutId: f.dut_id, files: [] })
    }
    groups.get(f.dut_id)!.files.push(f)
  }
  for (const g of groups.values()) {
    g.files.sort((a, b) => {
      const aRT = isRuntimeLog(a) ? 0 : 1
      const bRT = isRuntimeLog(b) ? 0 : 1
      if (aRT !== bRT) return aRT - bRT
      return a.path.localeCompare(b.path)
    })
  }
  return [...groups.values()].sort((a, b) => a.dutId.localeCompare(b.dutId))
})

function isRuntimeLog(f: { path: string }): boolean {
  return RUNTIME_LOG_PATTERNS.test(f.path)
}

const checkedFiles = computed(() => [...checkedPaths])

function isFileChecked(path: string): boolean {
  return checkedPaths.has(path)
}

function toggleFile(path: string) {
  if (checkedPaths.has(path)) {
    checkedPaths.delete(path)
  } else if (checkedPaths.size < MAX_FILES) {
    checkedPaths.add(path)
  }
}

function toggleGroupExpand(dutId: string) {
  if (expandedGroups.has(dutId)) expandedGroups.delete(dutId)
  else expandedGroups.add(dutId)
}

function isGroupFullyChecked(group: FileGroup): boolean {
  return group.files.every(f => checkedPaths.has(f.path))
}

function toggleGroupAll(group: FileGroup) {
  if (isGroupFullyChecked(group)) {
    for (const f of group.files) checkedPaths.delete(f.path)
  } else {
    for (const f of group.files) {
      if (checkedPaths.size >= MAX_FILES) break
      checkedPaths.add(f.path)
    }
  }
}

const dutFileMap = computed(() => {
  const map = new Map<string, string>()
  for (const f of manifestStore.fileIndex) {
    map.set(f.path, f.dut_id)
  }
  return map
})

function getDutForFile(path: string): string {
  return dutFileMap.value.get(path) ?? '—'
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

function cancelCorrelation() {
  cancelled.value = true
}

async function correlateAll() {
  loading.value = true
  loadProgress.value = 0
  currentFileName.value = ''
  cancelled.value = false
  events.value = []
  brushRange.value = null
  correlationRan.value = true

  const loader = new DataLoader()
  if (fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded) {
    loader.setFileMap(fileSystemStore.fileMap)
  }

  const filePaths = [...checkedPaths]
  const files: Array<{ path: string; content: string; index: number; category?: LogCategory }> = []

  for (let i = 0; i < filePaths.length; i++) {
    if (cancelled.value) break
    const path = filePaths[i]
    currentFileName.value = path.split('/').pop() ?? path
    const fileRef = manifestStore.fileIndex.find(f => f.path === path)
    if (!fileRef) continue
    try {
      const content = await loader.loadFile(fileRef)
      const cat = categoryFromCollectorId(fileRef.collector_id)
      files.push({ path, content, index: i, category: cat })
    } catch { /* skip unloadable */ }
    loadProgress.value = i + 1
  }

  if (!cancelled.value) {
    events.value = correlateFiles(files)
  }
  loading.value = false
  currentFileName.value = ''
}

const timelineEvents = computed<TimelineEvent[]>(() =>
  events.value.map(e => ({
    timestamp: e.timestamp,
    source: e.source,
    sourceIndex: e.sourceIndex,
    level: e.level,
    message: e.line,
  }))
)

const brushedEvents = computed(() => {
  if (!brushRange.value) return events.value
  return events.value.filter(e =>
    e.timestamp >= brushRange.value!.start && e.timestamp <= brushRange.value!.end
  )
})

const categoryBreakdown = computed(() => {
  const counts = new Map<LogCategory, number>()
  for (const evt of events.value) {
    counts.set(evt.category, (counts.get(evt.category) ?? 0) + 1)
  }
  const total = events.value.length || 1
  return [...counts.entries()]
    .map(([category, count]) => ({ category, count, pct: Math.round(count / total * 100) }))
    .sort((a, b) => b.count - a.count)
})

function toggleCategory(cat: LogCategory) {
  if (activeCategories.has(cat)) {
    activeCategories.delete(cat)
  } else {
    activeCategories.add(cat)
  }
}

const displayedEvents = computed(() => {
  let evts = brushedEvents.value
  if (activeCategories.size > 0) evts = evts.filter(e => activeCategories.has(e.category))
  if (hiddenLevels.size > 0) evts = evts.filter(e => !hiddenLevels.has(normalizeLevel(e.level)))
  if (levelFilter.value) evts = evts.filter(e => e.level === levelFilter.value)
  if (searchFilter.value) {
    const q = searchFilter.value.toLowerCase()
    evts = evts.filter(e => e.line.toLowerCase().includes(q))
  }
  return evts.slice(0, 10000)
})

const displayedEventsRef = computed(() => displayedEvents.value)

const virtualScroll = useVirtualScroll(
  displayedEventsRef,
  containerHeight,
  EVENT_ROW_HEIGHT,
  20,
)

function onBrushRange(range: { start: number; end: number } | null) {
  brushRange.value = range
}

function normalizeLevel(level?: string): string {
  switch (level?.toLowerCase()) {
    case 'error': case 'critical': case 'fatal': return 'error'
    case 'warning': case 'warn': return 'warning'
    case 'info': case 'notice': return 'info'
    default: return 'debug'
  }
}

function onLevelFilter(levels: Set<string>) {
  hiddenLevels.clear()
  for (const l of levels) hiddenLevels.add(l)
  levelFilter.value = ''
}

function toggleListLevel(key: string) {
  if (hiddenLevels.has(key)) hiddenLevels.delete(key)
  else hiddenLevels.add(key)
}

function onSelectEvent(index: number) {
  const evt = displayedEvents.value[index]
  if (evt) selectedEvent.value = evt
  highlightedIndex.value = index
  setTimeout(() => { highlightedIndex.value = -1 }, 2000)
}

function selectEventFromList(evt: CorrelationEvent) {
  selectedEvent.value = evt
}

function navigateToFile(evt: CorrelationEvent) {
  router.push(`/file/${encodeURIComponent(evt.source)}`)
}

function scrollToEventInList() {
  if (!selectedEvent.value) return
  const idx = displayedEvents.value.indexOf(selectedEvent.value)
  if (idx < 0) return
  const el = eventListRef.value
  if (el) el.scrollTop = idx * EVENT_ROW_HEIGHT - el.clientHeight / 2
  highlightedIndex.value = idx
  setTimeout(() => { highlightedIndex.value = -1 }, 2000)
}

function formatTimestamp(ts: number): string {
  if (ts < 1e10) return ts.toFixed(3) + 's'
  try { return new Date(ts).toISOString().replace('T', ' ').slice(0, 23) } catch { return String(ts) }
}

function formatTimeRange(): string {
  if (events.value.length < 2) return '\u2014'
  const first = events.value[0].timestamp
  const last = events.value[events.value.length - 1].timestamp
  if (first < 1e10) return `${first.toFixed(1)}s — ${last.toFixed(1)}s`
  return `${formatTimestamp(first)} — ${formatTimestamp(last)}`
}

function extractMessage(line: string): string {
  const idx = line.indexOf(']', line.indexOf(']') + 1)
  const msg = idx > 0 ? line.slice(idx + 1).trim() : line
  return msg || line
}

function autoSelectRuntimeLogs() {
  checkedPaths.clear()
  for (const group of fileGroups.value) {
    for (const f of group.files) {
      if (checkedPaths.size >= MAX_FILES) return
      if (isRuntimeLog(f)) {
        checkedPaths.add(f.path)
      }
    }
  }
}

watch(dutScope, () => {
  checkedPaths.clear()
  events.value = []
  correlationRan.value = false
  nextTick(autoSelectRuntimeLogs)
})

watch(fileGroups, () => {
  for (const g of fileGroups.value) {
    expandedGroups.add(g.dutId)
  }
}, { immediate: true })

onMounted(() => {
  if (manifestStore.duts.length > 3) {
    dutScope.value = manifestStore.duts[0]?.id ?? 'all'
  }
  nextTick(() => {
    autoSelectRuntimeLogs()
    if (checkedPaths.size > 0) {
      nextTick(correlateAll)
    }
  })
  const el = eventListRef.value
  if (el) {
    const ro = new ResizeObserver(() => {
      containerHeight.value = el.clientHeight || 500
    })
    ro.observe(el)
  }
})
</script>

<style scoped>
.corr-page { display: flex; flex-direction: column; gap: 12px; }

.corr-subtitle {
  font-size: 0.8125rem;
  color: var(--nv-text-secondary);
  margin: 0 0 4px;
}

/* Controls */
.corr-controls { padding: 16px; }
.corr-controls__top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.corr-controls__scope {
  display: flex;
  align-items: center;
  gap: 8px;
}
.corr-controls__label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--nv-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.corr-controls__actions {
  display: flex;
  align-items: center;
  gap: 10px;
}
.corr-controls__file-count {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  font-family: var(--nv-font-mono);
}

/* File picker */
.corr-file-picker {
  max-height: 280px;
  overflow-y: auto;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
}
.corr-file-group__header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  background: var(--nv-glass-bg-light);
  border-bottom: 1px solid var(--nv-glass-border);
  cursor: pointer;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--nv-text-primary);
}
.corr-file-group__header:hover { background: var(--nv-glass-bg); }
.corr-file-group__chevron {
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  width: 12px;
}
.corr-file-group__dut { color: var(--nv-accent); }
.corr-file-group__count {
  font-size: 0.6875rem;
  font-weight: 400;
  color: var(--nv-text-tertiary);
}
.corr-file-group__files {
  display: flex;
  flex-direction: column;
}
.corr-file-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px 3px 28px;
  font-size: 0.75rem;
  cursor: pointer;
  transition: background 0.1s;
}
.corr-file-item:hover { background: var(--nv-glass-bg-light); }
.corr-file-item--disabled { opacity: 0.4; cursor: not-allowed; }
.corr-file-item input { accent-color: var(--nv-accent); flex-shrink: 0; }
.corr-file-item__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.corr-file-item__name {
  font-weight: 500;
  color: var(--nv-text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}
.corr-file-item__meta {
  font-family: var(--nv-font-mono);
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
}
.corr-file-item__size {
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
  min-width: 50px;
  text-align: right;
}
.corr-file-item__badge {
  font-size: 0.5625rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 1px 5px;
  border-radius: 4px;
  background: var(--nv-accent);
  color: #000;
  flex-shrink: 0;
}

/* Category bar */
.corr-category-bar {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  border-radius: var(--nv-radius-md);
  flex-wrap: wrap;
}
.corr-category-bar__label {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  font-weight: 600;
  margin-right: 4px;
}
.corr-cat-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border-radius: 12px;
  font-size: 0.6875rem;
  border: 1px solid var(--nv-glass-border);
  background: var(--nv-glass-bg-light);
  cursor: pointer;
  color: var(--nv-text-secondary);
  transition: all 0.15s ease;
}
.corr-cat-chip:hover { border-color: var(--cat-color); }
.corr-cat-chip--active {
  border-color: var(--cat-color);
  background: color-mix(in srgb, var(--cat-color) 15%, transparent);
  color: var(--cat-color);
  font-weight: 600;
}
.corr-cat-chip__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.corr-cat-chip__count {
  font-weight: 600;
  opacity: 0.7;
}

/* Stats */
.corr-stats {
  display: flex;
  gap: 20px;
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
}

.corr-timeline-panel { margin-bottom: 4px; }

/* Event list */
.corr-list-panel { padding: 0; overflow: hidden; }
.corr-list__toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--nv-glass-border);
}
.corr-list__level-pills {
  display: flex;
  gap: 3px;
}
.corr-lvl-pill {
  padding: 2px 7px;
  border-radius: 10px;
  font-size: 0.625rem;
  font-weight: 600;
  border: 1px solid var(--nv-glass-border);
  background: transparent;
  color: var(--nv-text-tertiary);
  cursor: pointer;
  transition: all 0.15s ease;
  opacity: 0.5;
}
.corr-lvl-pill:hover { opacity: 0.8; }
.corr-lvl-pill--active {
  border-color: var(--lvl-color);
  background: color-mix(in srgb, var(--lvl-color) 12%, transparent);
  color: var(--lvl-color);
  opacity: 1;
}
.corr-list__count {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  margin-left: auto;
}
.corr-list__events {
  max-height: calc(100vh - 620px);
  min-height: 200px;
  overflow-y: auto;
}
.corr-list__row {
  display: flex;
  gap: 8px;
  align-items: center;
  padding: 0 12px;
  border-left: 3px solid transparent;
  cursor: pointer;
  font-family: var(--nv-font-mono, monospace);
  font-size: 0.75rem;
  line-height: 1;
  transition: background 0.1s;
  box-sizing: border-box;
}
.corr-list__row:hover { background: var(--nv-glass-bg-light); }
.corr-list__row--highlight {
  background: color-mix(in srgb, var(--nv-accent) 15%, transparent);
  animation: corr-flash 0.6s ease;
}
@keyframes corr-flash {
  0% { background: color-mix(in srgb, var(--nv-accent) 30%, transparent); }
  100% { background: color-mix(in srgb, var(--nv-accent) 15%, transparent); }
}
.corr-list__ts {
  color: var(--nv-text-tertiary);
  flex-shrink: 0;
  width: 145px;
  font-size: 0.625rem;
}
.corr-list__dut {
  color: var(--nv-accent);
  flex-shrink: 0;
  width: 60px;
  font-size: 0.625rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}
.corr-list__src {
  flex-shrink: 0;
  width: 130px;
  font-size: 0.625rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.corr-list__level {
  flex-shrink: 0;
  font-weight: 600;
  font-size: 0.625rem;
  width: 55px;
}
.corr-list__level--error, .corr-list__level--critical { color: var(--nv-error); }
.corr-list__level--warning, .corr-list__level--warn { color: var(--nv-warning); }
.corr-list__level--info, .corr-list__level--notice { color: var(--nv-info); }
.corr-list__level--debug { color: var(--nv-text-tertiary); }
.corr-list__msg {
  flex: 1;
  color: var(--nv-text-primary);
  word-break: break-all;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.corr-list__line {
  flex-shrink: 0;
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  width: 40px;
  text-align: right;
}
.corr-list__row--selected {
  background: color-mix(in srgb, var(--nv-accent) 10%, transparent);
  border-left-color: var(--nv-accent) !important;
}

/* Event detail panel */
.corr-detail {
  border-radius: var(--nv-radius-md);
  overflow: hidden;
}
.corr-detail__header {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-bottom: 1px solid var(--nv-glass-border);
}
.corr-detail__title {
  font-size: 0.6875rem;
  font-weight: 700;
  color: var(--nv-text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.corr-detail__body { padding: 10px 12px; }
.corr-detail__meta {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.corr-detail__badge {
  font-weight: 600;
  font-size: 0.75rem;
  font-family: var(--nv-font-mono);
}
.corr-detail__content {
  font-family: var(--nv-font-mono, monospace);
  font-size: 0.75rem;
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-light);
  padding: 10px 12px;
  border-radius: 6px;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 120px;
  overflow-y: auto;
  line-height: 1.5;
}
.corr-detail-enter-active, .corr-detail-leave-active {
  transition: all 0.2s ease;
}
.corr-detail-enter-from, .corr-detail-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
