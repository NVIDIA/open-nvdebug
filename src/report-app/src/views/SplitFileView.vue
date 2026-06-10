<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="split-view" style="margin-left: 260px;">
    <div class="split-view__header nv-glass--accent">
      <span style="font-weight: 600; font-size: 0.8125rem;">Side-by-Side File Comparison</span>
      <span style="font-size: 0.6875rem; color: var(--nv-text-tertiary);">Ctrl+\ to toggle split view</span>
      <span style="flex: 1;"></span>
      <router-link v-if="leftPath" :to="`/file/${encodeURIComponent(leftPath)}`" class="nv-btn nv-btn--ghost nv-btn--sm" style="text-decoration: none;">
        Exit Split View
      </router-link>
    </div>

    <div class="split-view__panels">
      <!-- Left panel -->
      <div class="split-view__panel">
        <div class="split-view__picker">
          <label style="font-size: 0.6875rem; color: var(--nv-text-secondary); margin-right: 6px;">Left:</label>
          <select v-model="leftPath" class="nv-select nv-select--sm" style="flex: 1;">
            <option value="">Select a file...</option>
            <option v-for="f in fileOptions" :key="f.path" :value="f.path">{{ f.label }}</option>
          </select>
        </div>
        <div class="split-view__content nv-glass--subtle">
          <pre v-if="leftContent" class="split-view__pre">{{ leftContent }}</pre>
          <EmptyState v-else icon="file" title="Select a file to compare" />
        </div>
      </div>

      <!-- Divider -->
      <div class="split-view__divider"></div>

      <!-- Right panel -->
      <div class="split-view__panel">
        <div class="split-view__picker">
          <label style="font-size: 0.6875rem; color: var(--nv-text-secondary); margin-right: 6px;">Right:</label>
          <select v-model="rightPath" class="nv-select nv-select--sm" style="flex: 1;">
            <option value="">Select a file...</option>
            <option v-for="f in fileOptions" :key="f.path" :value="f.path">{{ f.label }}</option>
          </select>
        </div>
        <div class="split-view__content nv-glass--subtle">
          <pre v-if="rightContent" class="split-view__pre">{{ rightContent }}</pre>
          <EmptyState v-else icon="file" title="Select a file to compare" />
        </div>
      </div>
    </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { DataLoader } from '@/services/dataLoader'
import EmptyState from '@/components/common/EmptyState.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'

const route = useRoute()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()

const leftPath = ref('')
const rightPath = ref('')
const leftContent = ref('')
const rightContent = ref('')

const dataLoader = new DataLoader()
if (fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded) {
  dataLoader.setFileMap(fileSystemStore.fileMap)
}

watch(() => fileSystemStore.directoryLoaded, (loaded) => {
  if (loaded && fileSystemStore.mode === 'file') {
    dataLoader.setFileMap(fileSystemStore.fileMap)
  }
})

const fileOptions = computed(() =>
  manifestStore.fileIndex
    .filter(f => f.type !== 'binary')
    .map(f => ({
      path: f.path,
      label: `${f.dut_id} / ${f.collector_id} / ${f.path.split('/').pop()}`,
    }))
    .sort((a, b) => a.label.localeCompare(b.label))
)

onMounted(() => {
  const q = route.query
  if (q.left) leftPath.value = String(q.left)
  if (q.right) rightPath.value = String(q.right)
})

async function loadFileContent(path: string): Promise<string> {
  try {
    const fileRef = manifestStore.fileIndex.find(f => f.path === path)
    if (!fileRef) return `[File not found: ${path}]`
    return await dataLoader.loadFile(fileRef)
  } catch {
    return `[Error loading file: ${path}]`
  }
}

watch(leftPath, async (path) => {
  if (path) leftContent.value = await loadFileContent(path)
  else leftContent.value = ''
})

watch(rightPath, async (path) => {
  if (path) rightContent.value = await loadFileContent(path)
  else rightContent.value = ''
})
</script>

<style scoped>
.split-view {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 52px);
}

.split-view__header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  border-bottom: 1px solid var(--nv-glass-border);
}

.split-view__panels {
  display: flex;
  flex: 1;
  min-height: 0;
}

.split-view__panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.split-view__picker {
  display: flex;
  align-items: center;
  padding: 6px 12px;
  border-bottom: 1px solid var(--nv-glass-border);
}

.split-view__content {
  flex: 1;
  overflow: auto;
  padding: 8px;
}

.split-view__pre {
  font-family: var(--nv-font-mono);
  font-size: 0.75rem;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  color: var(--nv-text-primary);
}

.split-view__divider {
  width: 4px;
  background: var(--nv-glass-border);
  cursor: col-resize;
  flex-shrink: 0;
}
.split-view__divider:hover {
  background: var(--nv-accent);
}
</style>
