<template>
  <div class="nv-page" :class="{ 'fv-fullscreen': isFullscreen }">
    <!-- file:// mode without a picked directory: gate the file viewer before
         calling DataLoader so we don't surface a bogus "file not found" error. -->
    <div v-if="needsPicker" class="nv-glass nv-glass--elevated" style="padding: var(--nv-space-4);">
      <p style="font-weight: 600; margin: 0 0 8px;">Select the report folder to view files</p>
      <p style="color: var(--nv-text-secondary); font-size: 0.8125rem; margin: 0 0 12px;">
        You are viewing this report from disk (<code>file://</code>). To open log files, click
        <strong>Select Folder</strong> in the banner above and choose the
        parent folder that contains <code>reports/</code> and the DUT directories.
      </p>
      <p v-if="fileRef" style="color: var(--nv-text-secondary); font-size: 0.75rem; margin: 0;">
        Requested: <code>{{ filePath }}</code>
      </p>
    </div>

    <!-- Loading -->
    <PageLoader v-else-if="loading" message="Loading file..." />

    <!-- Error -->
    <div v-else-if="error" class="nv-glass nv-glass--elevated" style="padding: var(--nv-space-4); border-color: var(--nv-error);">
      <p style="color: var(--nv-error); font-weight: 600; margin: 0 0 8px;">Failed to load file</p>
      <p style="color: var(--nv-text-secondary); font-size: 0.8125rem; margin: 0 0 8px;">{{ error }}</p>
      <p style="color: var(--nv-text-secondary); font-size: 0.75rem; margin: 0 0 12px;">
        Path: {{ filePath }} | Size: {{ formatBytes(fileRef?.size ?? 0) }} | Type: {{ fileRef?.type }}
      </p>
      <div style="display: flex; gap: 8px;">
        <button v-if="retryCount < 2" @click="loadFile" class="nv-btn nv-btn--primary">Retry</button>
        <!-- In http mode we can link directly. In file:// mode cross-origin
             navigation is blocked, so only show the link if the content was
             already loaded (blob download path in downloadFile()). -->
        <a v-if="fileRef && fileSystemStore.mode === 'http'" :href="downloadUrl" download class="nv-btn">Download Original</a>
        <button v-else-if="fileRef && content" @click="downloadFile" class="nv-btn">Download</button>
      </div>
    </div>

    <!-- Content loaded -->
    <template v-else-if="fileRef">
      <!-- Breadcrumbs (hidden in fullscreen) -->
      <Breadcrumbs v-if="!isFullscreen" :items="breadcrumbs" />

      <!-- File info bar -->
      <div class="nv-glass nv-glass--subtle file-info-bar">
        <h2 class="nv-page__title" style="font-size: 1rem; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px;" :title="fileName">{{ fileName }}</h2>
        <span class="nv-badge nv-badge--neutral">{{ fileRef.type.toUpperCase() }}</span>
        <span style="font-size: 0.75rem; color: var(--nv-text-secondary);">{{ formatBytes(fileRef.size) }}</span>

        <!-- Action buttons (primary — always visible) -->
        <div class="fv-actions fv-actions--primary">
          <button v-if="viewerType !== 'download'" class="fv-action-btn" title="Copy contents (C)" aria-label="Copy file contents" @click="copyContents">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M5 11H3.5A1.5 1.5 0 012 9.5V3.5A1.5 1.5 0 013.5 2h6A1.5 1.5 0 0111 3.5V5"/></svg>
            <span class="fv-action-btn__label">Copy</span>
          </button>
          <button class="fv-action-btn" title="Download file (D)" aria-label="Download file" @click="downloadFile">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2v8m0 0l-3-3m3 3l3-3M3 12v1.5A1.5 1.5 0 004.5 15h7a1.5 1.5 0 001.5-1.5V12"/></svg>
            <span class="fv-action-btn__label">Download</span>
          </button>
          <button class="fv-action-btn" title="Copy link" aria-label="Copy shareable link" @click="copyLink">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6.5 9.5l3-3M9 12l1.5-1.5a3 3 0 000-4.24l-.26-.26a3 3 0 00-4.24 0L4.5 7.5"/><path d="M7 4L5.5 5.5a3 3 0 000 4.24l.26.26a3 3 0 004.24 0L11.5 8.5"/></svg>
            <span class="fv-action-btn__label">Link</span>
          </button>
        </div>

        <!-- Action buttons (secondary — collapse into overflow on narrow screens) -->
        <div class="fv-actions fv-actions--secondary">
          <button v-if="viewerType !== 'download'" class="fv-action-btn" :class="{ 'fv-action-btn--active': !wrapEnabled }" title="Toggle word wrap (W)" aria-label="Toggle word wrap" @click="toggleWrap">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 3h12M2 7h8.5a2.5 2.5 0 010 5H8l1.5-1.5M8 12.5L9.5 14M2 11h3"/></svg>
            <span class="fv-action-btn__label">Wrap</span>
          </button>
          <button class="fv-action-btn" title="File metadata (I)" aria-label="File metadata" @click="showMeta = !showMeta">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="6.5"/><path d="M8 7v4M8 5v.5"/></svg>
            <span class="fv-action-btn__label">Info</span>
          </button>
          <button class="fv-action-btn" title="Toggle fullscreen (F)" aria-label="Toggle fullscreen" @click="toggleFullscreen">
            <svg v-if="!isFullscreen" width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 6V3.5A1.5 1.5 0 013.5 2H6M10 2h2.5A1.5 1.5 0 0114 3.5V6M14 10v2.5a1.5 1.5 0 01-1.5 1.5H10M6 14H3.5A1.5 1.5 0 012 12.5V10"/></svg>
            <svg v-else width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 2v2.5A1.5 1.5 0 014.5 6H2M10 2v2.5A1.5 1.5 0 0011.5 6H14M14 10h-2.5a1.5 1.5 0 00-1.5 1.5V14M2 10h2.5A1.5 1.5 0 016 11.5V14"/></svg>
            <span class="fv-action-btn__label">{{ isFullscreen ? 'Exit' : 'Full' }}</span>
          </button>
        </div>

        <!-- Overflow menu for narrow screens -->
        <div class="fv-overflow-wrap">
          <button class="fv-action-btn fv-overflow-trigger" aria-label="More actions" @click.stop="overflowOpen = !overflowOpen">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><circle cx="3" cy="8" r="1.5"/><circle cx="8" cy="8" r="1.5"/><circle cx="13" cy="8" r="1.5"/></svg>
          </button>
          <div v-if="overflowOpen" class="fv-overflow-menu" @click="overflowOpen = false">
            <button v-if="viewerType !== 'download'" class="fv-overflow-menu__item" @click="toggleWrap">
              {{ wrapEnabled ? '✓' : '\u00A0' }} Word Wrap
            </button>
            <button class="fv-overflow-menu__item" @click="showMeta = !showMeta">
              File Info
            </button>
            <button class="fv-overflow-menu__item" @click="toggleFullscreen">
              {{ isFullscreen ? 'Exit Fullscreen' : 'Fullscreen' }}
            </button>
            <button class="fv-overflow-menu__item" @click="showShortcuts = !showShortcuts">
              Keyboard Shortcuts
            </button>
          </div>
        </div>

        <span style="flex: 1;" />

        <!-- Prev/Next navigation -->
        <div v-if="siblingFiles.length > 1" class="fv-sibling-nav">
          <button @click="navigateSibling(-1)" :disabled="currentIndex <= 0" class="nv-btn nv-btn--sm" aria-label="Previous file">← Prev</button>
          <span style="font-size: 0.75rem; color: var(--nv-text-secondary); padding: 4px 8px; white-space: nowrap;">
            {{ currentIndex + 1 }} / {{ siblingFiles.length }}
          </span>
          <button @click="navigateSibling(1)" :disabled="currentIndex >= siblingFiles.length - 1" class="nv-btn nv-btn--sm" aria-label="Next file">Next →</button>
        </div>
      </div>

      <!-- Metadata drawer -->
      <Transition name="fv-drawer">
        <div v-if="showMeta" class="fv-meta-drawer">
          <div class="fv-meta-drawer__grid">
            <span class="fv-meta-drawer__label">Path</span>
            <span class="fv-meta-drawer__value fv-meta-drawer__value--mono">
              {{ filePath }}
              <button class="fv-action-btn fv-action-btn--inline" title="Copy path" @click="copyText(filePath, 'Path copied')">
                <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M5 11H3.5A1.5 1.5 0 012 9.5V3.5A1.5 1.5 0 013.5 2h6A1.5 1.5 0 0111 3.5V5"/></svg>
              </button>
            </span>

            <span class="fv-meta-drawer__label">DUT</span>
            <span class="fv-meta-drawer__value">
              <router-link v-if="fileRef.dut_id" :to="`/dut/${fileRef.dut_id}`" class="fv-meta-drawer__link">{{ fileRef.dut_id }}</router-link>
              <span v-else class="fv-meta-drawer__empty">&mdash;</span>
            </span>

            <span class="fv-meta-drawer__label">Group</span>
            <span class="fv-meta-drawer__value">
              <router-link v-if="fileRef.dut_id && fileRef.collector_group" :to="`/dut/${fileRef.dut_id}/${fileRef.collector_group}`" class="fv-meta-drawer__link">{{ fileRef.collector_group }}</router-link>
              <span v-else>{{ fileRef.collector_group || '\u2014' }}</span>
            </span>

            <span class="fv-meta-drawer__label">Collector</span>
            <span class="fv-meta-drawer__value">
              <router-link v-if="fileRef.dut_id && fileRef.collector_id" :to="`/dut/${fileRef.dut_id}/collector/${fileRef.collector_id}`" class="fv-meta-drawer__link">{{ fileRef.collector_id }}</router-link>
              <span v-else>{{ fileRef.collector_id || '\u2014' }}</span>
              <span v-if="fileRef.collector_name" style="color: var(--nv-text-tertiary); margin-left: 6px;">{{ fileRef.collector_name }}</span>
            </span>

            <span class="fv-meta-drawer__label">Type</span>
            <span class="fv-meta-drawer__value">{{ fileRef.type }} &middot; {{ formatBytes(fileRef.size) }}</span>

            <span class="fv-meta-drawer__label">Viewer</span>
            <span class="fv-meta-drawer__value">{{ viewerType }}</span>
          </div>
        </div>
      </Transition>

      <!-- Truncation warning -->
      <div v-if="isTruncated" class="nv-banner nv-banner--warning" style="margin-bottom: 12px;">
        File appears truncated (loaded {{ formatBytes(content.length * 2) }} but expected {{ formatBytes(fileRef.size) }})
      </div>

      <!-- Binary detection fallback -->
      <div v-if="detectedBinary" class="nv-banner" style="margin-bottom: 12px; font-size: 0.8125rem; color: var(--nv-info);">
        Binary content detected — showing hex preview
      </div>

      <!-- Invalid JSON fallback banner -->
      <div v-if="jsonParseError" class="nv-banner" style="margin-bottom: 12px; font-size: 0.8125rem; color: var(--nv-info);">
        Invalid JSON — showing raw content
      </div>

      <!-- Viewer wrapped in glass container -->
      <div class="nv-glass viewer-container">
        <ErrorBoundary>
          <DownloadCard
            v-if="viewerType === 'download'"
            :file-name="fileName"
            :file-size="fileRef.size"
            :file-type="fileRef.type"
            :download-url="downloadUrl"
          />

          <HexViewer
            v-else-if="detectedBinary"
            :content="content"
          />

          <template v-else-if="viewerType === 'json-tree'">
            <JsonTreeViewer v-if="!jsonParseError" :content="content" :height="viewerHeight" />
            <MonacoViewer v-else :content="content" language="json" :file-name="fileName" :height="viewerHeight" :word-wrap="wrapEnabled" />
          </template>

          <LogViewer
            v-else-if="viewerType === 'log-viewer'"
            :content="content"
            :height="viewerHeight"
          />

          <MonacoViewer
            v-else
            :content="content"
            :file-name="fileName"
            :disable-minimap="fileRef.size > 10_000_000"
            :height="viewerHeight"
            :word-wrap="wrapEnabled"
          />
        </ErrorBoundary>
      </div>
    </template>

    <!-- Keyboard Shortcuts Overlay -->
    <Teleport to="body">
      <Transition name="fv-fade">
        <div v-if="showShortcuts" class="fv-shortcuts-overlay" @click.self="showShortcuts = false">
          <div class="fv-shortcuts-panel">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
              <h3 style="margin: 0; font-size: 0.9375rem; font-weight: 600;">Keyboard Shortcuts</h3>
              <button class="nv-btn nv-btn--ghost nv-btn--sm" @click="showShortcuts = false" aria-label="Close">&times;</button>
            </div>
            <div class="fv-shortcuts-panel__list">
              <div class="fv-shortcut-row" v-for="s in shortcuts" :key="s.key">
                <kbd class="fv-kbd">{{ s.key }}</kbd>
                <span>{{ s.desc }}</span>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { DataLoader } from '@/services/dataLoader'
import { getViewerType, isBinaryContent } from '@/composables/useFileViewer'
import { showToast } from '@/composables/useToast'
import { copyToClipboard } from '@/utils/clipboard'
import { wordWrap } from '@/composables/useViewerPrefs'
import type { FileEntry } from '@/types/manifest'
import MonacoViewer from '@/components/viewers/MonacoViewer.vue'
import LogViewer from '@/components/viewers/LogViewer.vue'
import JsonTreeViewer from '@/components/viewers/JsonTreeViewer.vue'
import DownloadCard from '@/components/viewers/DownloadCard.vue'
import HexViewer from '@/components/viewers/HexViewer.vue'
import ErrorBoundary from '@/components/common/ErrorBoundary.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'

const route = useRoute()
const router = useRouter()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()

const content = ref('')
const loading = ref(false)
const error = ref<string | null>(null)
const retryCount = ref(0)
const detectedBinary = ref(false)
const jsonParseError = ref(false)
const isFullscreen = ref(false)
const showMeta = ref(false)
const showShortcuts = ref(false)
const overflowOpen = ref(false)
const wrapEnabled = ref(wordWrap.value)

watch(wrapEnabled, (v) => { wordWrap.value = v })

const dataLoader = new DataLoader()

if (fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded) {
  dataLoader.setFileMap(fileSystemStore.fileMap)
}

const filePath = computed(() => {
  const encoded = route.params.encodedPath
  return typeof encoded === 'string' ? decodeURIComponent(encoded) : Array.isArray(encoded) ? encoded.join('/') : ''
})

const fileName = computed(() => filePath.value.split('/').pop() ?? filePath.value)

const fileRef = computed<FileEntry | undefined>(() =>
  manifestStore.fileIndex.find(f => f.path === filePath.value)
)

const downloadUrl = computed(() => '../' + filePath.value)

const viewerType = computed(() => {
  if (!fileRef.value) return 'monaco'
  return getViewerType(fileRef.value)
})

const viewerHeight = computed(() => isFullscreen.value ? 'calc(100vh - 80px)' : 'calc(100vh - 260px)')

const needsPicker = computed(() => fileSystemStore.needsDirectoryPicker)

const breadcrumbs = computed(() => {
  const items: { label: string; to?: string }[] = [{ label: 'Home', to: '/' }]
  if (fileRef.value?.dut_id) {
    items.push({ label: fileRef.value.dut_id, to: `/dut/${fileRef.value.dut_id}` })
  }
  if (fileRef.value?.collector_group) {
    items.push({
      label: fileRef.value.collector_group,
      to: fileRef.value.dut_id ? `/dut/${fileRef.value.dut_id}/${fileRef.value.collector_group}` : undefined
    })
  }
  items.push({ label: fileName.value })
  return items
})

const isTruncated = computed(() => {
  if (!fileRef.value || !content.value) return false
  return content.value.length > 0 && content.value.length * 2 < fileRef.value.size * 0.5
})

const siblingFiles = computed<FileEntry[]>(() => {
  if (!fileRef.value) return []
  return manifestStore.fileIndex
    .filter(f => f.collector_id === fileRef.value!.collector_id && f.dut_id === fileRef.value!.dut_id)
    .sort((a, b) => a.path.localeCompare(b.path))
})

const currentIndex = computed(() =>
  siblingFiles.value.findIndex(f => f.path === filePath.value)
)

const shortcuts = computed(() => [
  { key: '[', desc: 'Previous file' },
  { key: ']', desc: 'Next file' },
  ...(viewerType.value !== 'download' ? [{ key: 'C', desc: 'Copy file contents' }] : []),
  { key: 'D', desc: 'Download file' },
  ...(viewerType.value !== 'download' ? [{ key: 'W', desc: 'Toggle word wrap' }] : []),
  { key: 'F', desc: 'Toggle fullscreen' },
  { key: 'I', desc: 'Toggle file info' },
  { key: 'Ctrl+F', desc: 'Find in file' },
  { key: '?', desc: 'Toggle this help' },
  { key: 'Esc', desc: 'Exit fullscreen / close overlay' },
])

// --- Actions ---
function navigateSibling(delta: number) {
  const newIndex = currentIndex.value + delta
  if (newIndex >= 0 && newIndex < siblingFiles.value.length) {
    router.push(`/file/${encodeURIComponent(siblingFiles.value[newIndex].path)}`)
  }
}

function copyContents() {
  if (!content.value) return
  copyToClipboard(content.value).then(
    () => showToast('Copied to clipboard', 'success'),
    () => showToast('Failed to copy', 'error'),
  )
}

function downloadFile() {
  const a = document.createElement('a')
  if (content.value) {
    let blobUrl = ''
    try {
      const blob = new Blob([content.value], { type: 'application/octet-stream' })
      blobUrl = URL.createObjectURL(blob)
      a.href = blobUrl
      a.download = fileName.value
      a.click()
    } finally {
      if (blobUrl) setTimeout(() => URL.revokeObjectURL(blobUrl), 500)
    }
  } else {
    a.href = downloadUrl.value
    a.download = fileName.value
    a.click()
  }
  showToast('Download started', 'success')
}

function copyLink() {
  const url = window.location.origin + window.location.pathname + '#/file/' + encodeURIComponent(filePath.value)
  copyToClipboard(url).then(
    () => showToast('Link copied', 'success'),
    () => showToast('Failed to copy', 'error'),
  )
}

function copyText(text: string, msg: string) {
  copyToClipboard(text).then(
    () => showToast(msg, 'success'),
    () => showToast('Failed to copy', 'error'),
  )
}

function toggleWrap() {
  wrapEnabled.value = !wrapEnabled.value
  showToast(wrapEnabled.value ? 'Word wrap on' : 'Word wrap off', 'info')
}

function toggleFullscreen() {
  isFullscreen.value = !isFullscreen.value
}

// --- File loading ---
async function loadFile() {
  if (!fileRef.value || viewerType.value === 'download') return
  // In file:// mode we cannot fetch subresources. Wait for the user to pick
  // the report directory (handled by the directoryLoaded watcher below) rather
  // than surfacing a misleading "file not found" error.
  if (fileSystemStore.mode === 'file' && !fileSystemStore.directoryLoaded) return

  loading.value = true
  error.value = null
  detectedBinary.value = false
  jsonParseError.value = false

  try {
    const ref = fileRef.value
    content.value = await dataLoader.loadFile(ref)

    if (isBinaryContent(content.value)) {
      detectedBinary.value = true
      return
    }

    if (ref.type === 'json') {
      try {
        JSON.parse(content.value)
      } catch {
        jsonParseError.value = true
      }
    }
  } catch (e) {
    retryCount.value++
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

watch(filePath, () => {
  retryCount.value = 0
  loadFile()
}, { immediate: true })

watch(() => fileSystemStore.directoryLoaded, (loaded) => {
  if (loaded) {
    dataLoader.setFileMap(fileSystemStore.fileMap)
    loadFile()
  }
})

// --- Keyboard shortcuts ---
function onKeydown(e: KeyboardEvent) {
  if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return

  if (e.key === 'Escape') {
    if (showShortcuts.value) { showShortcuts.value = false; return }
    if (showMeta.value) { showMeta.value = false; return }
    if (isFullscreen.value) { isFullscreen.value = false; return }
    return
  }

  if (e.key === '?') { showShortcuts.value = !showShortcuts.value; return }
  if (e.key === '[') navigateSibling(-1)
  if (e.key === ']') navigateSibling(1)

  const upper = e.key.toUpperCase()
  const isViewable = viewerType.value !== 'download'
  if (!e.ctrlKey && !e.metaKey && !e.altKey) {
    if (upper === 'C' && isViewable) { copyContents(); return }
    if (upper === 'D') { e.preventDefault(); downloadFile(); return }
    if (upper === 'W' && isViewable) { toggleWrap(); return }
    if (upper === 'F') { toggleFullscreen(); return }
    if (upper === 'I') { showMeta.value = !showMeta.value; return }
  }
}

function onClickOutsideOverflow() { overflowOpen.value = false }

onMounted(() => {
  document.addEventListener('keydown', onKeydown)
  document.addEventListener('click', onClickOutsideOverflow)
})
onUnmounted(() => {
  document.removeEventListener('keydown', onKeydown)
  document.removeEventListener('click', onClickOutsideOverflow)
})

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}
</script>

<style scoped>
/* --- File info bar --- */
.file-info-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 12px 0;
  padding: 8px 12px;
  flex-wrap: wrap;
}

/* --- Action buttons --- */
.fv-actions {
  display: flex;
  align-items: center;
  gap: 2px;
}

.fv-action-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 5px 8px;
  border: 1px solid transparent;
  border-radius: var(--nv-radius-sm);
  background: none;
  color: var(--nv-text-secondary);
  font: inherit;
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
}
.fv-action-btn:hover {
  background: var(--nv-bg-tertiary);
  color: var(--nv-text-primary);
  border-color: var(--nv-glass-border);
}
.fv-action-btn--active {
  color: var(--nv-accent);
}
.fv-action-btn--inline {
  padding: 2px 4px;
  vertical-align: middle;
}
.fv-action-btn__label {
  font-size: 0.6875rem;
  font-weight: 500;
}

/* --- Overflow menu (narrow screens) --- */
.fv-overflow-wrap {
  position: relative;
  display: none;
}
.fv-overflow-trigger {
  padding: 5px 6px;
}
.fv-overflow-menu {
  position: absolute;
  top: 100%;
  right: 0;
  z-index: 100;
  min-width: 180px;
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
  padding: 4px 0;
  margin-top: 4px;
}
.fv-overflow-menu__item {
  display: block;
  width: 100%;
  padding: 8px 14px;
  border: none;
  background: none;
  color: var(--nv-text-primary);
  font: inherit;
  font-size: 0.8125rem;
  text-align: left;
  cursor: pointer;
}
.fv-overflow-menu__item:hover {
  background: color-mix(in srgb, var(--nv-accent) 10%, transparent);
}

@media (max-width: 900px) {
  .fv-actions--secondary { display: none; }
  .fv-overflow-wrap { display: block; }
  .fv-action-btn__label { display: none; }
}
@media (max-width: 640px) {
  .fv-sibling-nav { display: none; }
}

/* --- Sibling nav --- */
.fv-sibling-nav {
  display: flex;
  gap: 4px;
  align-items: center;
}

/* --- Metadata drawer --- */
.fv-meta-drawer {
  background: var(--nv-glass-bg);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  padding: 12px 16px;
  margin-bottom: 12px;
  font-size: 0.8125rem;
}
.fv-meta-drawer__grid {
  display: grid;
  grid-template-columns: 80px 1fr;
  gap: 6px 16px;
  align-items: baseline;
}
.fv-meta-drawer__label {
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  font-weight: 600;
}
.fv-meta-drawer__value {
  color: var(--nv-text-primary);
  word-break: break-all;
}
.fv-meta-drawer__value--mono {
  font-family: var(--nv-font-mono);
  font-size: 0.75rem;
}
.fv-meta-drawer__link {
  color: var(--nv-accent);
  text-decoration: none;
}
.fv-meta-drawer__link:hover {
  text-decoration: underline;
}
.fv-meta-drawer__empty {
  color: var(--nv-text-tertiary);
}

.fv-drawer-enter-active,
.fv-drawer-leave-active {
  transition: all 0.2s ease;
  overflow: hidden;
}
.fv-drawer-enter-from,
.fv-drawer-leave-to {
  max-height: 0;
  opacity: 0;
  padding-top: 0;
  padding-bottom: 0;
  margin-bottom: 0;
}
.fv-drawer-enter-to,
.fv-drawer-leave-from {
  max-height: 200px;
  opacity: 1;
}

/* --- Fullscreen --- */
.fv-fullscreen {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: var(--nv-bg);
  padding: 8px 16px;
  overflow-y: auto;
}

/* --- Viewer container --- */
.viewer-container {
  padding: 2px;
  overflow: hidden;
}
.viewer-container :deep(.monaco-editor),
.viewer-container :deep(.nv-log),
.viewer-container :deep(.json-tree) {
  border-radius: var(--nv-radius-lg);
}

/* --- Shortcuts overlay --- */
.fv-shortcuts-overlay {
  position: fixed;
  inset: 0;
  z-index: 2000;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
}
.fv-shortcuts-panel {
  background: var(--nv-glass-bg-dense);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-lg);
  padding: 20px 24px;
  min-width: 320px;
  max-width: 400px;
  box-shadow: 0 16px 48px rgba(0, 0, 0, 0.3);
}
.fv-shortcuts-panel__list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.fv-shortcut-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 0.8125rem;
  color: var(--nv-text-secondary);
}
.fv-kbd {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  padding: 2px 8px;
  font-family: var(--nv-font-mono);
  font-size: 0.6875rem;
  font-weight: 600;
  background: var(--nv-bg-tertiary);
  border: 1px solid var(--nv-glass-border);
  border-radius: 4px;
  color: var(--nv-text-primary);
  box-shadow: 0 1px 0 var(--nv-glass-border);
}

.fv-fade-enter-active,
.fv-fade-leave-active {
  transition: opacity 0.2s ease;
}
.fv-fade-enter-from,
.fv-fade-leave-to {
  opacity: 0;
}
</style>
