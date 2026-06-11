<template>
  <div class="nv-log json-tree-viewer" @click="closeContextMenu">
    <!-- Toolbar -->
    <div class="nv-log__toolbar">
      <div class="json-tree-viewer__search-group">
        <input
          ref="searchInputRef"
          v-model="searchText"
          type="text"
          placeholder="Search keys/values..."
          class="nv-input nv-input--sm"
          style="width: 220px;"
          @keydown.enter.exact="goToNextMatch"
          @keydown.shift.enter="goToPrevMatch"
        />
        <template v-if="searchText && matchPaths.length > 0">
          <span class="json-tree-viewer__match-count">
            {{ currentMatchIndex + 1 }}/{{ matchPaths.length }}
          </span>
          <button
            class="nv-btn nv-btn--ghost nv-btn--sm json-tree-viewer__nav-btn"
            title="Previous match (Shift+Enter)"
            aria-label="Previous match"
            @click="goToPrevMatch"
          >&#9650;</button>
          <button
            class="nv-btn nv-btn--ghost nv-btn--sm json-tree-viewer__nav-btn"
            title="Next match (Enter)"
            aria-label="Next match"
            @click="goToNextMatch"
          >&#9660;</button>
        </template>
        <span v-else-if="searchText" class="json-tree-viewer__match-count json-tree-viewer__match-count--zero">
          0 matches
        </span>
      </div>

      <button @click="expandAll" class="nv-btn nv-btn--sm" aria-label="Expand all">Expand All</button>
      <button @click="collapseAll" class="nv-btn nv-btn--sm" aria-label="Collapse all">Collapse All</button>
      <span style="flex: 1;" />

      <!-- JSON Path Display -->
      <div v-if="hoveredPath" class="json-tree-viewer__path-bar">
        <span class="json-tree-viewer__path-text">{{ hoveredPath }}</span>
        <button @click="doCopyPath(hoveredPath)" class="nv-btn nv-btn--ghost nv-btn--sm" title="Copy path" aria-label="Copy JSON path">
          &#128203;
        </button>
        <button @click="doCopyValue(hoveredPath)" class="nv-btn nv-btn--ghost nv-btn--sm" title="Copy value" aria-label="Copy value at path">
          &#128196;
        </button>
      </div>

      <button @click="showRaw = !showRaw" class="nv-btn nv-btn--sm">
        {{ showRaw ? 'Tree View' : 'Raw JSON' }}
      </button>
    </div>

    <!-- Raw JSON (Monaco) -->
    <div v-if="showRaw">
      <MonacoViewer :content="rawJson" language="json" :height="height" :word-wrap="wordWrap" />
    </div>

    <!-- Tree View -->
    <div v-else ref="treeContainer" class="nv-log__content" :style="{ height: height, padding: '12px' }" @mouseover="onHover">
      <JsonNode
        :data="parsedData"
        :path="'$'"
        :depth="0"
        :search="searchText"
        :expanded-paths="expandedPaths"
        @toggle="togglePath"
        @contextmenu-node="onNodeContext"
      />
    </div>

    <!-- Context Menu -->
    <Teleport to="body">
      <div
        v-if="ctxMenu.visible"
        class="json-ctx-menu"
        :style="{ top: ctxMenu.y + 'px', left: ctxMenu.x + 'px' }"
        @click.stop
      >
        <button class="json-ctx-menu__item" @click="ctxCopyKey">
          <span class="json-ctx-menu__icon">K</span> Copy Key
        </button>
        <button class="json-ctx-menu__item" @click="ctxCopyValue">
          <span class="json-ctx-menu__icon">V</span> Copy Value
        </button>
        <button class="json-ctx-menu__item" @click="ctxCopyPath">
          <span class="json-ctx-menu__icon">P</span> Copy Path
        </button>
        <div v-if="ctxMenu.isExpandable" class="json-ctx-menu__separator" />
        <button v-if="ctxMenu.isExpandable" class="json-ctx-menu__item" @click="ctxExpandChildren">
          <span class="json-ctx-menu__icon">&#9660;</span> Expand Children
        </button>
        <button v-if="ctxMenu.isExpandable" class="json-ctx-menu__item" @click="ctxCollapseChildren">
          <span class="json-ctx-menu__icon">&#9654;</span> Collapse Children
        </button>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from 'vue'
import MonacoViewer from './MonacoViewer.vue'
import JsonNode from './JsonNode.vue'
import { showToast } from '@/composables/useToast'
import { copyToClipboard } from '@/utils/clipboard'
import { jsonRawMode, wordWrap } from '@/composables/useViewerPrefs'

const props = withDefaults(defineProps<{
  content: string
  height?: string
}>(), {
  height: '500px',
})

const searchText = ref('')
const showRaw = ref(jsonRawMode.value)
const expandedPaths = ref(new Set<string>(['$']))
const hoveredPath = ref('')
const treeContainer = ref<HTMLElement>()
const searchInputRef = ref<HTMLInputElement>()
const currentMatchIndex = ref(0)

watch(showRaw, (v) => { jsonRawMode.value = v })

const parsedData = computed(() => {
  try {
    return JSON.parse(props.content)
  } catch {
    return { __parse_error__: 'Invalid JSON' }
  }
})

const rawJson = computed(() => {
  try {
    return JSON.stringify(JSON.parse(props.content), null, 2)
  } catch {
    return props.content
  }
})

// --- Search match collection ---
const matchPaths = computed(() => {
  if (!searchText.value) return [] as string[]
  const q = searchText.value.toLowerCase()
  const results: string[] = []
  function walk(data: any, path: string, label?: string) {
    if (data !== null && typeof data === 'object') {
      if (label?.toLowerCase().includes(q)) results.push(path)
      for (const key of Object.keys(data)) {
        walk(data[key], `${path}.${key}`, key)
      }
    } else {
      const display = data === null ? 'null' : typeof data === 'string' ? `"${data}"` : String(data)
      if (display.toLowerCase().includes(q) || (label?.toLowerCase().includes(q) ?? false)) {
        results.push(path)
      }
    }
  }
  walk(parsedData.value, '$')
  return results
})

watch(searchText, () => { currentMatchIndex.value = 0 })

function ensurePathExpanded(path: string) {
  const parts = path.split('.')
  let current = ''
  for (let i = 0; i < parts.length - 1; i++) {
    current = i === 0 ? parts[0] : `${current}.${parts[i]}`
    expandedPaths.value.add(current)
  }
}

function scrollToMatch(path: string) {
  ensurePathExpanded(path)
  nextTick(() => {
    if (!treeContainer.value) return
    const el = treeContainer.value.querySelector(`[data-json-path="${CSS.escape(path)}"]`)
    if (el) {
      el.scrollIntoView({ block: 'center', behavior: 'smooth' })
      el.classList.add('json-tree-viewer__flash')
      setTimeout(() => el.classList.remove('json-tree-viewer__flash'), 1200)
    }
  })
}

function goToNextMatch() {
  if (matchPaths.value.length === 0) return
  currentMatchIndex.value = (currentMatchIndex.value + 1) % matchPaths.value.length
  scrollToMatch(matchPaths.value[currentMatchIndex.value])
}

function goToPrevMatch() {
  if (matchPaths.value.length === 0) return
  currentMatchIndex.value = (currentMatchIndex.value - 1 + matchPaths.value.length) % matchPaths.value.length
  scrollToMatch(matchPaths.value[currentMatchIndex.value])
}

// --- Tree operations ---
function togglePath(path: string) {
  if (expandedPaths.value.has(path)) {
    expandedPaths.value.delete(path)
  } else {
    expandedPaths.value.add(path)
  }
}

function onHover(e: MouseEvent) {
  const target = e.target as HTMLElement
  const nodeEl = target.closest('[data-json-path]') as HTMLElement | null
  if (nodeEl?.dataset.jsonPath) {
    hoveredPath.value = nodeEl.dataset.jsonPath
  }
}

function resolveValue(path: string): any {
  const parts = path.replace(/^\$\.?/, '').split('.')
  let current: any = parsedData.value
  for (const part of parts) {
    if (!part) continue
    if (current == null || typeof current !== 'object') return undefined
    current = current[part]
  }
  return current
}

function doCopyPath(path: string) {
  copyToClipboard(path).then(
    () => showToast('Path copied', 'success'),
    () => showToast('Failed to copy', 'error'),
  )
}

function doCopyValue(path: string) {
  const value = resolveValue(path)
  const text = typeof value === 'object' && value !== null ? JSON.stringify(value, null, 2) : String(value ?? '')
  copyToClipboard(text).then(
    () => showToast('Value copied', 'success'),
    () => showToast('Failed to copy', 'error'),
  )
}

function expandAll() {
  const paths = new Set<string>()
  function walk(data: any, path: string) {
    paths.add(path)
    if (data && typeof data === 'object') {
      for (const key of Object.keys(data)) {
        walk(data[key], `${path}.${key}`)
      }
    }
  }
  walk(parsedData.value, '$')
  expandedPaths.value = paths
}

function collapseAll() {
  expandedPaths.value = new Set(['$'])
}

// --- Context Menu ---
interface CtxMenuState {
  visible: boolean
  x: number
  y: number
  path: string
  key: string
  data: any
  isExpandable: boolean
}

const ctxMenu = ref<CtxMenuState>({
  visible: false, x: 0, y: 0, path: '', key: '', data: null, isExpandable: false,
})

function onNodeContext(payload: { event: MouseEvent; path: string; key: string; data: any; isExpandable: boolean }) {
  const vw = window.innerWidth
  const vh = window.innerHeight
  let x = payload.event.clientX
  let y = payload.event.clientY
  const menuW = 200
  const menuH = payload.isExpandable ? 200 : 120
  if (x + menuW > vw) x = vw - menuW - 8
  if (y + menuH > vh) y = vh - menuH - 8
  ctxMenu.value = { visible: true, x, y, path: payload.path, key: payload.key, data: payload.data, isExpandable: payload.isExpandable }
}

function closeContextMenu() {
  ctxMenu.value.visible = false
}

function ctxCopyKey() {
  copyToClipboard(ctxMenu.value.key).then(
    () => showToast(`Key "${ctxMenu.value.key}" copied`, 'success'),
    () => showToast('Failed to copy', 'error'),
  )
  closeContextMenu()
}

function ctxCopyValue() {
  const d = ctxMenu.value.data
  const text = typeof d === 'object' && d !== null ? JSON.stringify(d, null, 2) : String(d ?? '')
  copyToClipboard(text).then(
    () => showToast('Value copied', 'success'),
    () => showToast('Failed to copy', 'error'),
  )
  closeContextMenu()
}

function ctxCopyPath() {
  copyToClipboard(ctxMenu.value.path).then(
    () => showToast('Path copied', 'success'),
    () => showToast('Failed to copy', 'error'),
  )
  closeContextMenu()
}

function ctxExpandChildren() {
  const base = ctxMenu.value.path
  const data = ctxMenu.value.data
  function walk(d: any, p: string) {
    expandedPaths.value.add(p)
    if (d && typeof d === 'object') {
      for (const key of Object.keys(d)) walk(d[key], `${p}.${key}`)
    }
  }
  walk(data, base)
  closeContextMenu()
}

function ctxCollapseChildren() {
  const base = ctxMenu.value.path
  const toRemove: string[] = []
  for (const p of expandedPaths.value) {
    if (p.startsWith(base + '.')) toRemove.push(p)
  }
  for (const p of toRemove) expandedPaths.value.delete(p)
  closeContextMenu()
}

function onDocClick() { closeContextMenu() }
function onEscKey(e: KeyboardEvent) { if (e.key === 'Escape') closeContextMenu() }
onMounted(() => {
  document.addEventListener('click', onDocClick)
  document.addEventListener('keydown', onEscKey)
})
onUnmounted(() => {
  document.removeEventListener('click', onDocClick)
  document.removeEventListener('keydown', onEscKey)
})
</script>

<style scoped>
.json-tree-viewer__search-group {
  display: flex;
  align-items: center;
  gap: 4px;
}
.json-tree-viewer__match-count {
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  padding: 2px 8px;
  background: var(--nv-bg-tertiary);
  border-radius: var(--nv-radius-sm);
  white-space: nowrap;
  font-family: var(--nv-font-mono);
}
.json-tree-viewer__match-count--zero {
  color: var(--nv-text-tertiary);
}
.json-tree-viewer__nav-btn {
  padding: 2px 6px !important;
  font-size: 0.625rem !important;
  line-height: 1;
  min-width: 0;
}
.json-tree-viewer__path-bar {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
  font-family: var(--nv-font-mono);
  max-width: 400px;
  overflow: hidden;
}
.json-tree-viewer__path-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  direction: rtl;
  text-align: left;
}

/* Flash animation for search navigation */
:deep(.json-tree-viewer__flash) {
  animation: jsonFlash 1.2s ease;
}
@keyframes jsonFlash {
  0%, 100% { background: transparent; }
  15% { background: color-mix(in srgb, var(--nv-accent) 25%, transparent); }
  50% { background: color-mix(in srgb, var(--nv-accent) 12%, transparent); }
}

/* Context Menu */
.json-ctx-menu {
  position: fixed;
  z-index: 2000;
  min-width: 180px;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
  padding: 4px 0;
  font-size: 0.8125rem;
}
.json-ctx-menu__item {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 7px 14px;
  border: none;
  background: none;
  color: var(--nv-text-primary);
  font: inherit;
  font-size: 0.8125rem;
  cursor: pointer;
  text-align: left;
}
.json-ctx-menu__item:hover {
  background: color-mix(in srgb, var(--nv-accent) 12%, transparent);
}
.json-ctx-menu__icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  font-size: 0.625rem;
  font-weight: 700;
  border-radius: 3px;
  background: var(--nv-bg-tertiary);
  color: var(--nv-text-secondary);
  flex-shrink: 0;
}
.json-ctx-menu__separator {
  height: 1px;
  background: var(--nv-glass-border);
  margin: 4px 8px;
}
</style>
