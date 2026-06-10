<template>
  <Teleport to="body">
    <div v-if="open" @click.self="close" @keydown.escape="close" tabindex="-1" ref="overlayRef"
      class="nv-command-overlay">
      <div class="nv-command">
        <!-- Input -->
        <div class="nv-command__input">
          <input
            ref="inputRef"
            v-model="query"
            type="text"
            :placeholder="placeholder"
            @keydown.down.prevent="selectedIndex = Math.min(selectedIndex + 1, filteredResults.length - 1)"
            @keydown.up.prevent="selectedIndex = Math.max(selectedIndex - 1, 0)"
            @keydown.enter="selectCurrent"
          />
        </div>

        <!-- Results -->
        <div class="nv-command__results">
          <div v-if="filteredResults.length === 0" class="nv-empty">
            {{ query ? 'No results found' : 'Type to search files, collectors, DUTs...' }}
          </div>
          <div
            v-for="(result, i) in filteredResults"
            :key="i"
            @click="select(result)"
            :class="['nv-command__item', i === selectedIndex && 'nv-command__item--active']"
          >
            <span style="width: 20px; text-align: center; font-size: 0.875rem; flex-shrink: 0;">{{ typeIcon(result.type) }}</span>
            <div style="flex: 1; min-width: 0;">
              <div style="font-size: 0.8125rem; color: var(--nv-text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{{ result.label }}</div>
              <div style="font-size: 0.6875rem; color: var(--nv-text-secondary);">{{ result.sublabel }}</div>
            </div>
            <span class="nv-badge nv-badge--neutral">{{ result.type }}</span>
          </div>
        </div>

        <!-- Hint -->
        <div class="nv-command__hint">
          <span><kbd>&#x2191;&#x2193;</kbd> navigate</span>
          <span><kbd>Enter</kbd> select</span>
          <span><kbd>Esc</kbd> close</span>
          <span style="flex: 1;" />
          <span>Type <code>&gt;</code> for commands, <code>@</code> for collectors, <code>#</code> for DUTs</span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useSearch, type SearchResult } from '@/composables/useSearch'
import { useThemeStore } from '@/stores/theme'
import { useSearchStore } from '@/stores/search'

const open = ref(false)
const query = ref('')
const selectedIndex = ref(0)
const inputRef = ref<HTMLInputElement>()
const overlayRef = ref<HTMLElement>()

const router = useRouter()
const themeStore = useThemeStore()
const searchStore = useSearchStore()
const searchComposable = useSearch()

// Commands available with > prefix
const commands: Array<{ label: string; action: () => void }> = [
  { label: 'Toggle Theme (Light/Dark)', action: () => themeStore.toggle() },
  { label: 'Go to Timing Analysis', action: () => router.push('/timing') },
  { label: 'Go to File Map', action: () => router.push('/file-map') },
  { label: 'Go to Health Heatmap', action: () => router.push('/heatmap') },
  { label: 'Go to All Errors', action: () => router.push('/errors') },
  { label: 'Go to DUT Comparison', action: () => router.push('/compare') },
  { label: 'Open Cross-File Search', action: () => { searchStore.grepPanelOpen = true } },
  { label: 'Go to Gantt Timeline', action: () => router.push('/timing/gantt') },
]

const placeholder = computed(() => {
  if (query.value.startsWith('>')) return 'Type a command...'
  if (query.value.startsWith('@')) return 'Search collectors by ID...'
  if (query.value.startsWith('#')) return 'Search DUTs...'
  return 'Search files, collectors, DUTs... (> for commands)'
})

const filteredResults = computed<Array<SearchResult | { type: string; label: string; sublabel: string; path: string; action?: () => void }>>(() => {
  const q = query.value.trim()

  // > prefix: commands
  if (q.startsWith('>')) {
    const cmdQuery = q.slice(1).trim().toLowerCase()
    return commands
      .filter(c => !cmdQuery || c.label.toLowerCase().includes(cmdQuery))
      .map(c => ({ type: 'command', label: c.label, sublabel: '', path: '', action: c.action, score: 100 }))
  }

  // @ prefix: collector IDs
  if (q.startsWith('@')) {
    const idQuery = q.slice(1).trim()
    if (idQuery) {
      searchComposable.query.value = idQuery
    }
    return searchComposable.results.value.filter(r => r.type === 'collector')
  }

  // # prefix: DUT names
  if (q.startsWith('#')) {
    const dutQuery = q.slice(1).trim()
    if (dutQuery) {
      searchComposable.query.value = dutQuery
    }
    return searchComposable.results.value.filter(r => r.type === 'dut')
  }

  // Default: search everything
  if (q) {
    searchComposable.query.value = q
  }
  return searchComposable.results.value
})

watch(query, () => { selectedIndex.value = 0 })

function select(result: any) {
  if (result.action) {
    result.action()
  } else if (result.path) {
    router.push(result.path)
  }
  close()
}

function selectCurrent() {
  if (filteredResults.value.length > 0) {
    select(filteredResults.value[selectedIndex.value])
  }
}

function show() {
  open.value = true
  query.value = ''
  selectedIndex.value = 0
  nextTick(() => {
    inputRef.value?.focus()
    overlayRef.value?.focus()
  })
}

function close() {
  open.value = false
  query.value = ''
}

function typeIcon(type: string): string {
  switch (type) {
    case 'file': return '\u{1F4C4}'
    case 'dut': return '\u{1F5A5}'
    case 'collector': return '\u{1F4E6}'
    case 'error': return '\u274C'
    case 'command': return '\u26A1'
    default: return '\u{1F50D}'
  }
}

defineExpose({ show, close, isOpen: open })
</script>
