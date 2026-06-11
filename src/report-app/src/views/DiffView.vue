<template>
  <div style="min-height: calc(100vh - 88px);">
    <div class="nv-sidebar"><AnalysisNav /></div>
    <div class="nv-page" style="margin-left: 260px;">
    <Breadcrumbs :items="[{ label: 'Dashboard', to: '/' }, { label: 'File Diff' }]" />

    <h2 class="nv-page__title" style="margin: 16px 0 20px;">File Diff</h2>

    <!-- File selectors -->
    <div class="nv-card" style="margin-bottom: 16px;">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
        <div>
          <label style="font-size: 0.75rem; color: var(--nv-text-secondary); display: block; margin-bottom: 4px;">Left file</label>
          <select v-model="leftPath" class="nv-select" style="width: 100%;">
            <option value="">Select a file...</option>
            <option v-for="f in textFiles" :key="f.path" :value="f.path">{{ f.path }}</option>
          </select>
        </div>
        <div>
          <label style="font-size: 0.75rem; color: var(--nv-text-secondary); display: block; margin-bottom: 4px;">Right file</label>
          <select v-model="rightPath" class="nv-select" style="width: 100%;">
            <option value="">Select a file...</option>
            <option v-for="f in textFiles" :key="f.path" :value="f.path">{{ f.path }}</option>
          </select>
        </div>
      </div>
    </div>

    <PageLoader v-if="loading" message="Loading diff..." />
    <div v-else-if="error" style="color: var(--nv-error);">{{ error }}</div>

    <div v-else-if="leftContent !== null && rightContent !== null" class="nv-card" style="padding: 0; overflow: hidden;">
      <DiffViewer
        :original="leftContent"
        :modified="rightContent"
        :language="detectedLanguage"
        height="calc(100vh - 310px)"
      />
    </div>

    <div v-else class="nv-glass" style="padding: 40px; text-align: center; color: var(--nv-text-secondary); border-radius: 12px;">
      Select two files above to compare.
    </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { DataLoader } from '@/services/dataLoader'
import DiffViewer from '@/components/viewers/DiffViewer.vue'
import Breadcrumbs from '@/components/common/Breadcrumbs.vue'
import AnalysisNav from '@/components/common/AnalysisNav.vue'
import PageLoader from '@/components/common/PageLoader.vue'

const route = useRoute()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()

const leftPath = ref((route.query.left as string) ?? '')
const rightPath = ref((route.query.right as string) ?? '')
const leftContent = ref<string | null>(null)
const rightContent = ref<string | null>(null)
const loading = ref(false)
const error = ref('')

const textFiles = computed(() =>
  manifestStore.fileIndex.filter(f => f.type !== 'binary' && f.size < 10_000_000)
    .sort((a, b) => a.path.localeCompare(b.path))
)

const detectedLanguage = computed(() => {
  const ext = leftPath.value.split('.').pop()?.toLowerCase()
  const map: Record<string, string> = { json: 'json', yaml: 'yaml', yml: 'yaml', xml: 'xml', py: 'python', sh: 'shell' }
  return map[ext ?? ''] ?? 'plaintext'
})

async function loadFiles() {
  if (!leftPath.value || !rightPath.value) {
    leftContent.value = null
    rightContent.value = null
    return
  }

  loading.value = true
  error.value = ''

  const loader = new DataLoader()
  if (fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded) {
    loader.setFileMap(fileSystemStore.fileMap)
  }

  try {
    const leftRef = manifestStore.fileIndex.find(f => f.path === leftPath.value)
    const rightRef = manifestStore.fileIndex.find(f => f.path === rightPath.value)
    if (!leftRef || !rightRef) throw new Error('File not found in manifest')

    const [left, right] = await Promise.all([
      loader.loadFile(leftRef),
      loader.loadFile(rightRef),
    ])
    leftContent.value = left
    rightContent.value = right
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

watch([leftPath, rightPath], loadFiles, { immediate: true })
</script>
