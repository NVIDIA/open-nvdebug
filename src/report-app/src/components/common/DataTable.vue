<template>
  <div :class="['dt-root', { 'dt-root--fill': fillViewport }, `dt-density--${density}`]" ref="rootRef">
    <!-- Toolbar: search + actions -->
    <div class="dt-toolbar">
      <div v-if="searchable" class="dt-search">
        <svg class="dt-search__icon" width="14" height="14" viewBox="0 0 16 16" fill="none">
          <circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.5"/>
          <path d="M11 11l3.5 3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        <input
          v-model="searchText"
          type="text"
          :placeholder="`Filter ${data.length} rows...`"
          class="dt-search__input"
          @keydown="onSearchKeydown"
        />
        <button v-if="searchText" class="dt-search__clear" @click="searchText = ''" title="Clear filter">
          &times;
        </button>
      </div>
      <div class="dt-toolbar__right">
        <span class="dt-count">
          <template v-if="searchText && filteredRows.length !== data.length">
            {{ filteredRows.length }} of {{ data.length }}
          </template>
          <template v-else>
            {{ data.length }} {{ data.length === 1 ? 'row' : 'rows' }}
          </template>
        </span>

        <!-- Density toggle -->
        <div class="dt-density-toggle">
          <button
            v-for="d in (['compact', 'comfortable', 'spacious'] as const)"
            :key="d"
            :class="['dt-density-btn', { 'dt-density-btn--active': density === d }]"
            @click="density = d"
            :title="d"
          >
            <svg v-if="d === 'compact'" width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M2 3h12v1H2zm0 3h12v1H2zm0 3h12v1H2zm0 3h12v1H2z"/></svg>
            <svg v-else-if="d === 'comfortable'" width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M2 2h12v2H2zm0 4h12v2H2zm0 4h12v2H2z"/></svg>
            <svg v-else width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M2 1h12v3H2zm0 5h12v3H2zm0 5h12v3H2z"/></svg>
          </button>
        </div>

        <!-- Column visibility -->
        <div class="dt-col-toggle" v-if="columns.length > 3">
          <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="showColMenu = !showColMenu" title="Toggle columns">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M1 2h4v4H1zm0 5h4v4H1zm0 5h4v4H1zM6 2h4v4H6zm0 5h4v4H6zm0 5h4v4H6zM11 2h4v4h-4zm0 5h4v4h-4zm0 5h4v4h-4z" opacity=".6"/></svg>
          </button>
          <div v-if="showColMenu" class="dt-col-menu" @mouseleave="showColMenu = false">
            <label v-for="col in columns" :key="col.key" class="dt-col-menu__item">
              <input type="checkbox" :checked="visibleColKeys.has(col.key)" @change="toggleColumn(col.key)" />
              {{ col.label }}
            </label>
          </div>
        </div>

        <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="exportToClipboard" title="Copy table to clipboard">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
            <rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/>
            <path d="M11 5V3.5A1.5 1.5 0 009.5 2h-6A1.5 1.5 0 002 3.5v6A1.5 1.5 0 003.5 11H5" stroke="currentColor" stroke-width="1.5"/>
          </svg>
          Copy
        </button>
        <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="exportToCsv" title="Download as CSV">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
            <path d="M8 1v9M4 7l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M2 12v2h12v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          CSV
        </button>
      </div>
    </div>

    <!-- Per-column filter bar -->
    <div v-if="activeColumnFilters.size > 0" class="dt-active-filters">
      <span class="dt-active-filters__label">Filters:</span>
      <span v-for="[key, val] in activeColumnFilters" :key="key" class="dt-filter-chip">
        {{ columnLabel(key) }}: {{ val }}
        <button @click="clearColumnFilter(key)" class="dt-filter-chip__remove">&times;</button>
      </span>
      <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="activeColumnFilters.clear()" style="font-size: var(--nv-text-xs);">Clear all</button>
    </div>

    <!-- Table -->
    <div class="dt-scroll nv-table-viewport" :style="scrollStyle" @keydown="onTableKeydown" tabindex="0">
      <table class="nv-table">
        <thead>
          <tr>
            <th
              v-for="(col, ci) in visibleColumns"
              :key="col.key"
              @click="col.sortable !== false && toggleSort(col.key)"
              :data-sortable="col.sortable !== false ? '' : undefined"
              :class="['dt-th', { 'dt-th--sorted': sortKey === col.key, 'dt-th--sticky': ci === 0 && stickyFirstCol }]"
            >
              <span class="dt-th__content">
                {{ col.label }}
                <span v-if="col.sortable !== false" class="dt-sort-indicator">
                  <span v-if="sortKey !== col.key" class="dt-sort-indicator--idle">&#8645;</span>
                  <span v-else-if="sortDir === 'asc'" class="dt-sort-indicator--active">&#8593;</span>
                  <span v-else class="dt-sort-indicator--active">&#8595;</span>
                </span>
              </span>
              <button
                v-if="columnDistinctValues(col.key).length > 1 && columnDistinctValues(col.key).length <= 50"
                class="dt-col-filter-btn"
                @click.stop="toggleColumnFilterMenu(col.key)"
                :title="`Filter by ${col.label}`"
              >
                <svg width="10" height="10" viewBox="0 0 16 16" fill="currentColor" :opacity="activeColumnFilters.has(col.key) ? 1 : 0.4">
                  <path d="M1 1h14l-5.5 6.5V13l-3 2V7.5z"/>
                </svg>
              </button>
              <div v-if="columnFilterMenuKey === col.key" class="dt-col-filter-menu" @mouseleave="columnFilterMenuKey = ''">
                <div
                  v-for="val in columnDistinctValues(col.key)"
                  :key="val"
                  class="dt-col-filter-menu__item"
                  :class="{ 'dt-col-filter-menu__item--active': activeColumnFilters.get(col.key) === val }"
                  @click="setColumnFilter(col.key, val)"
                >{{ val }}</div>
                <div v-if="activeColumnFilters.has(col.key)" class="dt-col-filter-menu__item dt-col-filter-menu__item--clear" @click="clearColumnFilter(col.key)">
                  Clear filter
                </div>
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(row, i) in displayedRows"
            :key="i"
            @click="onRowClick($event, row)"
            :class="{ 'dt-row--focused': focusedRowIndex === i }"
            data-clickable
          >
            <td v-for="(col, ci) in visibleColumns" :key="col.key" :class="{ 'dt-td--sticky': ci === 0 && stickyFirstCol }">
              <slot :name="'cell-' + col.key" :row="row" :value="row[col.key]">
                <span v-if="searchText && shouldHighlight(cellText(row, col))" v-html="highlightMatch(cellText(row, col))"></span>
                <template v-else>{{ cellText(row, col) }}</template>
              </slot>
            </td>
          </tr>
        </tbody>
      </table>

      <EmptyState
        v-if="displayedRows.length === 0"
        :icon="searchText ? 'search' : 'data'"
        :title="searchText ? 'No matching rows' : 'No data'"
        :description="searchText ? 'Try adjusting your search query' : undefined"
      />
    </div>

    <!-- Footer: pagination -->
    <div class="dt-footer">
      <span class="dt-footer__info">
        <template v-if="effectivePageSize > 0">
          Showing {{ rangeStart }}&ndash;{{ rangeEnd }} of {{ totalFiltered }}
        </template>
        <template v-else>
          {{ filteredRows.length }} rows
        </template>
      </span>
      <div class="dt-footer__controls">
        <select v-model.number="selectedPageSize" class="nv-select nv-select--sm" style="width: 70px; font-size: 0.6875rem;" title="Rows per page">
          <option :value="10">10</option>
          <option :value="25">25</option>
          <option :value="50">50</option>
          <option :value="100">100</option>
          <option :value="0">All</option>
        </select>
        <template v-if="effectivePageSize > 0">
          <button class="nv-btn nv-btn--ghost nv-btn--sm" :disabled="currentPage === 0" @click="currentPage = 0" title="First page">
            &#171;
          </button>
          <button class="nv-btn nv-btn--ghost nv-btn--sm" :disabled="currentPage === 0" @click="currentPage--">
            Prev
          </button>
          <span class="dt-footer__page">{{ currentPage + 1 }} / {{ totalPages }}</span>
          <button class="nv-btn nv-btn--ghost nv-btn--sm" :disabled="currentPage >= totalPages - 1" @click="currentPage++">
            Next
          </button>
          <button class="nv-btn nv-btn--ghost nv-btn--sm" :disabled="currentPage >= totalPages - 1" @click="currentPage = totalPages - 1" title="Last page">
            &#187;
          </button>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, reactive } from 'vue'
import Fuse from 'fuse.js'
import { naturalCompare } from '@/utils/naturalSort'
import { showToast } from '@/composables/useToast'
import { copyToClipboard } from '@/utils/clipboard'
import EmptyState from '@/components/common/EmptyState.vue'

export interface Column {
  key: string
  label: string
  sortable?: boolean
  formatter?: (value: unknown, row: Record<string, any>) => string
}

const props = withDefaults(defineProps<{
  columns: Column[]
  data: Record<string, any>[]
  searchable?: boolean
  pageSize?: number
  fillViewport?: boolean
  stickyFirstCol?: boolean
}>(), {
  searchable: false,
  pageSize: 0,
  fillViewport: false,
  stickyFirstCol: false,
})

const emit = defineEmits<{
  'row-click': [row: Record<string, any>]
}>()

function onRowClick(event: MouseEvent, row: Record<string, any>) {
  const target = event.target as HTMLElement
  if (target.closest('a, button, input, select, textarea, [data-no-row-click]')) return
  emit('row-click', row)
}

const searchText = ref('')
const sortKey = ref('')
const sortDir = ref<'asc' | 'desc'>('asc')
const currentPage = ref(0)
const rootRef = ref<HTMLElement>()
const availableHeight = ref(600)
const density = ref<'compact' | 'comfortable' | 'spacious'>('comfortable')
const showColMenu = ref(false)
const visibleColKeys = reactive(new Set<string>())
const activeColumnFilters = reactive(new Map<string, string>())
const columnFilterMenuKey = ref('')
const focusedRowIndex = ref(-1)
const selectedPageSize = ref(props.pageSize)

// Initialize visible columns
watch(() => props.columns, (cols) => {
  if (visibleColKeys.size === 0) {
    for (const c of cols) visibleColKeys.add(c.key)
  }
}, { immediate: true })

const visibleColumns = computed(() =>
  props.columns.filter(c => visibleColKeys.has(c.key))
)

function toggleColumn(key: string) {
  if (visibleColKeys.has(key)) {
    if (visibleColKeys.size > 1) visibleColKeys.delete(key)
  } else {
    visibleColKeys.add(key)
  }
}

function columnLabel(key: string): string {
  return props.columns.find(c => c.key === key)?.label ?? key
}

watch(searchText, () => { currentPage.value = 0 })

function toggleSort(key: string) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDir.value = 'asc'
  }
}

function measureHeight() {
  if (!props.fillViewport || !rootRef.value) return
  const rect = rootRef.value.getBoundingClientRect()
  availableHeight.value = Math.max(300, window.innerHeight - rect.top - 120)
}

const scrollStyle = computed(() => {
  if (!props.fillViewport) return {}
  return { maxHeight: `${availableHeight.value}px` }
})

// Per-column distinct values (for filter dropdowns)
const columnDistinctCache = new Map<string, string[]>()
function columnDistinctValues(key: string): string[] {
  if (columnDistinctCache.has(key)) return columnDistinctCache.get(key)!
  const col = props.columns.find(c => c.key === key)
  const vals = new Set<string>()
  for (const row of props.data) {
    const v = row[key]
    const displayValue = displayCell(v, row, col)
    if (displayValue !== '') vals.add(displayValue)
  }
  const sorted = [...vals].sort()
  columnDistinctCache.set(key, sorted)
  return sorted
}
watch(() => props.data, () => columnDistinctCache.clear())

function toggleColumnFilterMenu(key: string) {
  columnFilterMenuKey.value = columnFilterMenuKey.value === key ? '' : key
}

function setColumnFilter(key: string, val: string) {
  activeColumnFilters.set(key, val)
  columnFilterMenuKey.value = ''
  currentPage.value = 0
}

function clearColumnFilter(key: string) {
  activeColumnFilters.delete(key)
  columnFilterMenuKey.value = ''
}

function displayCell(val: unknown, row: Record<string, any> = {}, col?: Column): string {
  if (col?.formatter) return col.formatter(val, row)
  if (val == null) return ''
  if (typeof val !== 'object') return String(val)
  try { return JSON.stringify(val) } catch { return String(val) }
}

function cellText(row: Record<string, any>, col: Column): string {
  return displayCell(row[col.key], row, col)
}

function shouldHighlight(text: string): boolean {
  if (!searchText.value || !text) return false
  return text.toLowerCase().includes(searchText.value.toLowerCase())
}

function highlightMatch(text: string): string {
  if (!searchText.value) return text
  const escaped = searchText.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return text.replace(
    new RegExp(`(${escaped})`, 'gi'),
    '<mark class="dt-highlight">$1</mark>'
  )
}

// Keyboard navigation
function onSearchKeydown(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') {
    e.preventDefault()
    focusedRowIndex.value = 0
  }
}

function onTableKeydown(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') {
    e.preventDefault()
    focusedRowIndex.value = Math.min(focusedRowIndex.value + 1, displayedRows.value.length - 1)
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    focusedRowIndex.value = Math.max(focusedRowIndex.value - 1, 0)
  } else if (e.key === 'Enter' && focusedRowIndex.value >= 0) {
    emit('row-click', displayedRows.value[focusedRowIndex.value])
  }
}

// Export
async function exportToClipboard() {
  const header = visibleColumns.value.map(c => c.label).join('\t')
  const rows = sortedRows.value.map(row =>
    visibleColumns.value.map(c => {
      return cellText(row, c)
    }).join('\t')
  )
  try {
    await copyToClipboard([header, ...rows].join('\n'))
    showToast(`Copied ${rows.length} rows to clipboard`, 'success')
  } catch {
    showToast('Copy failed', 'error')
  }
}

function exportToCsv() {
  const header = visibleColumns.value.map(c => csvEscape(c.label)).join(',')
  const rows = sortedRows.value.map(row =>
    visibleColumns.value.map(c => csvEscape(cellText(row, c))).join(',')
  )
  const csv = [header, ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'export.csv'
  a.click()
  URL.revokeObjectURL(url)
  showToast(`Downloaded ${rows.length} rows as CSV`, 'success')
}

function csvEscape(val: any): string {
  if (val == null) return ''
  const s = String(val)
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`
  }
  return s
}

let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  measureHeight()
  window.addEventListener('resize', measureHeight)
  if (rootRef.value) {
    resizeObserver = new ResizeObserver(measureHeight)
    resizeObserver.observe(rootRef.value)
  }
})

onUnmounted(() => {
  window.removeEventListener('resize', measureHeight)
  resizeObserver?.disconnect()
})

const fuseInstance = computed(() => {
  const keys = props.columns.map(c => c.key)
  return new Fuse(props.data, {
    keys,
    threshold: 0.35,
    ignoreLocation: true,
    includeMatches: true,
  })
})

const filteredRows = computed(() => {
  let rows: Record<string, any>[]
  if (searchText.value) {
    const results = fuseInstance.value.search(searchText.value)
    rows = results.map(r => r.item)
    const seen = new Set(rows)
    const query = searchText.value.toLowerCase()
    for (const row of props.data) {
      if (seen.has(row)) continue
      if (props.columns.some(col => cellText(row, col).toLowerCase().includes(query))) {
        rows.push(row)
        seen.add(row)
      }
    }
  } else {
    rows = [...props.data]
  }
  for (const [key, val] of activeColumnFilters) {
    const col = props.columns.find(c => c.key === key)
    rows = rows.filter(row => displayCell(row[key], row, col) === val)
  }
  return rows
})

const sortedRows = computed(() => {
  if (!sortKey.value) return filteredRows.value
  return [...filteredRows.value].sort((a, b) => {
    const va = a[sortKey.value]
    const vb = b[sortKey.value]
    if (va == null && vb == null) return 0
    if (va == null) return 1
    if (vb == null) return -1
    const cmp = typeof va === 'number' && typeof vb === 'number'
      ? va - vb
      : naturalCompare(String(va), String(vb))
    return sortDir.value === 'asc' ? cmp : -cmp
  })
})

const effectivePageSize = computed(() => selectedPageSize.value)
const totalFiltered = computed(() => sortedRows.value.length)
const totalPages = computed(() => effectivePageSize.value > 0 ? Math.max(1, Math.ceil(totalFiltered.value / effectivePageSize.value)) : 1)
const rangeStart = computed(() => totalFiltered.value === 0 ? 0 : currentPage.value * effectivePageSize.value + 1)
const rangeEnd = computed(() => Math.min((currentPage.value + 1) * effectivePageSize.value, totalFiltered.value))

const displayedRows = computed(() => {
  if (effectivePageSize.value > 0) {
    const start = currentPage.value * effectivePageSize.value
    return sortedRows.value.slice(start, start + effectivePageSize.value)
  }
  return sortedRows.value
})
</script>

<style scoped>
.dt-root {
  display: flex;
  flex-direction: column;
}
.dt-root--fill {
  flex: 1;
  min-height: 0;
}

/* Density modes */
.dt-density--compact :deep(.nv-table td),
.dt-density--compact :deep(.nv-table th) { padding: 2px 8px; font-size: 0.6875rem; }
.dt-density--comfortable :deep(.nv-table td),
.dt-density--comfortable :deep(.nv-table th) { padding: 6px 10px; }
.dt-density--spacious :deep(.nv-table td),
.dt-density--spacious :deep(.nv-table th) { padding: 10px 14px; }

.dt-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 0;
  flex-wrap: wrap;
}
.dt-toolbar__right {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
  flex-wrap: wrap;
}

.dt-search {
  display: flex;
  align-items: center;
  gap: 8px;
  position: relative;
  flex: 1;
  max-width: 360px;
}
.dt-search__icon {
  position: absolute;
  left: 10px;
  color: var(--nv-text-tertiary);
  pointer-events: none;
}
.dt-search__input {
  width: 100%;
  padding: 6px 28px 6px 32px;
  font-size: var(--nv-text-sm);
  font-family: var(--nv-font-family);
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-light);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  outline: none;
  transition: all var(--nv-duration-base) var(--nv-ease);
}
.dt-search__input:focus {
  border-color: var(--nv-accent);
  box-shadow: 0 0 0 3px var(--nv-accent-muted);
}
.dt-search__clear {
  position: absolute;
  right: 6px;
  background: none;
  border: none;
  cursor: pointer;
  color: var(--nv-text-tertiary);
  font-size: var(--nv-text-lg);
  line-height: 1;
  padding: 2px 4px;
  border-radius: var(--nv-radius-sm);
}
.dt-search__clear:hover {
  color: var(--nv-text-primary);
  background: var(--nv-bg-hover);
}

.dt-count {
  font-size: var(--nv-text-xs);
  color: var(--nv-text-tertiary);
  white-space: nowrap;
}

/* Density toggle */
.dt-density-toggle {
  display: flex;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-sm);
  overflow: hidden;
}
.dt-density-btn {
  background: none;
  border: none;
  padding: 3px 5px;
  cursor: pointer;
  color: var(--nv-text-tertiary);
  display: flex;
  align-items: center;
  transition: all 0.1s;
}
.dt-density-btn:hover { color: var(--nv-text-secondary); }
.dt-density-btn--active {
  background: var(--nv-accent);
  color: #000;
}

/* Column visibility menu */
.dt-col-toggle { position: relative; }
.dt-col-menu {
  position: absolute;
  top: 100%;
  right: 0;
  z-index: 20;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(12px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  padding: 6px 0;
  min-width: 160px;
  box-shadow: var(--nv-glass-shadow);
  max-height: 300px;
  overflow-y: auto;
}
.dt-col-menu__item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 12px;
  font-size: var(--nv-text-sm);
  color: var(--nv-text-secondary);
  cursor: pointer;
}
.dt-col-menu__item:hover { background: var(--nv-glass-bg-light); }
.dt-col-menu__item input { accent-color: var(--nv-accent); }

/* Active column filters bar */
.dt-active-filters {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 0;
  flex-wrap: wrap;
}
.dt-active-filters__label {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  font-weight: 600;
}
.dt-filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 0.6875rem;
  background: var(--nv-accent-muted);
  color: var(--nv-accent);
  font-weight: 600;
}
.dt-filter-chip__remove {
  background: none;
  border: none;
  cursor: pointer;
  color: inherit;
  font-size: var(--nv-text-base);
  line-height: 1;
  padding: 0 2px;
  opacity: 0.7;
}
.dt-filter-chip__remove:hover { opacity: 1; }

.dt-scroll {
  overflow-y: auto;
  overflow-x: auto;
  flex: 1;
  min-height: 0;
}

/* Table header */
.dt-th {
  position: relative;
}
.dt-th__content {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.dt-th--sorted {
  color: var(--nv-accent) !important;
}
.dt-th--sticky {
  position: sticky;
  left: 0;
  z-index: 2;
  background: var(--nv-glass-bg-dense);
}

.dt-sort-indicator {
  display: inline-flex;
  font-size: var(--nv-text-sm);
  line-height: 1;
}
.dt-sort-indicator--idle { opacity: 0.25; }
.dt-sort-indicator--active {
  color: var(--nv-accent);
  opacity: 1;
}

/* Per-column filter */
.dt-col-filter-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 2px;
  margin-left: 2px;
  border-radius: 3px;
  color: var(--nv-text-tertiary);
  display: inline-flex;
  vertical-align: middle;
}
.dt-col-filter-btn:hover { color: var(--nv-accent); background: var(--nv-glass-bg-light); }

.dt-col-filter-menu {
  position: absolute;
  top: 100%;
  left: 0;
  z-index: 20;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(12px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  padding: 4px 0;
  min-width: 120px;
  max-height: 240px;
  overflow-y: auto;
  box-shadow: var(--nv-glass-shadow);
}
.dt-col-filter-menu__item {
  padding: 4px 12px;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  cursor: pointer;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.dt-col-filter-menu__item:hover { background: var(--nv-glass-bg-light); }
.dt-col-filter-menu__item--active {
  background: var(--nv-accent-muted);
  color: var(--nv-accent);
  font-weight: 600;
}
.dt-col-filter-menu__item--clear {
  border-top: 1px solid var(--nv-glass-border);
  color: var(--nv-error);
  font-weight: 600;
}

/* Sticky first column for tbody */
.dt-td--sticky {
  position: sticky;
  left: 0;
  z-index: 1;
  background: var(--nv-glass-bg-dense);
}

/* Row focus for keyboard nav */
.dt-row--focused {
  outline: 2px solid var(--nv-accent);
  outline-offset: -2px;
}

/* Search highlight */
:deep(.dt-highlight) {
  background: var(--nv-accent-muted);
  color: var(--nv-accent);
  border-radius: 2px;
  padding: 0 1px;
  font-weight: 600;
}

.dt-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  border-top: 1px solid var(--nv-glass-border);
  font-size: var(--nv-text-xs);
  background: var(--nv-glass-bg-light);
  border-radius: 0 0 var(--nv-radius-lg) var(--nv-radius-lg);
  flex-wrap: wrap;
  gap: 8px;
}
.dt-footer__info {
  color: var(--nv-text-secondary);
}
.dt-footer__controls {
  display: flex;
  align-items: center;
  gap: 4px;
}
.dt-footer__page {
  font-size: var(--nv-text-xs);
  color: var(--nv-text-secondary);
  min-width: 55px;
  text-align: center;
}
</style>
