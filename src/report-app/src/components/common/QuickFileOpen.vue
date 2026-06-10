<template>
  <Teleport to="body">
    <div v-if="open" @click.self="close" @keydown.escape="close" tabindex="-1" ref="overlayRef"
      class="nv-command-overlay">
      <div class="nv-command" style="max-height: 50vh;">
        <div class="nv-command__input">
          <input
            ref="inputRef"
            v-model="query"
            type="text"
            placeholder="Go to file..."
            @keydown.down.prevent="selectedIndex = Math.min(selectedIndex + 1, results.length - 1)"
            @keydown.up.prevent="selectedIndex = Math.max(selectedIndex - 1, 0)"
            @keydown.enter="openSelected"
          />
        </div>
        <div class="nv-command__results">
          <!-- Recent files when empty -->
          <template v-if="!query && recentFiles.length > 0">
            <div class="nv-sidebar__section-title" style="padding: 4px 16px;">Recent</div>
          </template>

          <div
            v-for="(file, i) in results"
            :key="file.path"
            @click="openFile(file.path)"
            :class="['nv-command__item', i === selectedIndex && 'nv-command__item--active']"
          >
            <span style="font-size: 0.8125rem;">{{ fileIcon(file.type) }}</span>
            <div style="flex: 1; min-width: 0;">
              <div style="font-size: 0.8125rem; color: var(--nv-text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{{ file.path.split('/').pop() }}</div>
              <div style="font-size: 0.6875rem; color: var(--nv-text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{{ file.path }}</div>
            </div>
            <span style="font-size: 0.6875rem; color: var(--nv-text-secondary);">{{ formatSize(file.size) }}</span>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import type { FileEntry } from '@/types/manifest'

const open = ref(false)
const query = ref('')
const selectedIndex = ref(0)
const inputRef = ref<HTMLInputElement>()
const overlayRef = ref<HTMLElement>()
const recentFiles = ref<string[]>([])

const router = useRouter()
const manifestStore = useManifestStore()

const results = computed<FileEntry[]>(() => {
  const q = query.value.toLowerCase()
  if (!q) {
    // Show recent files
    return manifestStore.fileIndex.filter(f => recentFiles.value.includes(f.path)).slice(0, 10)
  }
  return manifestStore.fileIndex
    .filter(f => f.path.toLowerCase().includes(q))
    .sort((a, b) => {
      const aName = a.path.split('/').pop() ?? ''
      const bName = b.path.split('/').pop() ?? ''
      const aExact = aName.toLowerCase().startsWith(q) ? 0 : 1
      const bExact = bName.toLowerCase().startsWith(q) ? 0 : 1
      return aExact - bExact || aName.localeCompare(bName)
    })
    .slice(0, 30)
})

function openFile(path: string) {
  // Track recent
  recentFiles.value = [path, ...recentFiles.value.filter(p => p !== path)].slice(0, 20)
  router.push(`/file/${encodeURIComponent(path)}`)
  close()
}

function openSelected() {
  if (results.value.length > 0) {
    openFile(results.value[selectedIndex.value]?.path ?? results.value[0].path)
  }
}

function show() {
  open.value = true
  query.value = ''
  selectedIndex.value = 0
  nextTick(() => inputRef.value?.focus())
}

function close() { open.value = false }

function fileIcon(type: string): string {
  const icons: Record<string, string> = { json: '\u{1F4C4}', log: '\u{1F4DD}', text: '\u{1F4C3}', xml: '\u{1F4CB}', yaml: '\u2699', binary: '\u{1F4BE}' }
  return icons[type] ?? '\u{1F4C4}'
}

function formatSize(b: number): string {
  if (b < 1024) return b + 'B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(0) + 'KB'
  return (b / (1024 * 1024)).toFixed(1) + 'MB'
}

defineExpose({ show, close })
</script>
