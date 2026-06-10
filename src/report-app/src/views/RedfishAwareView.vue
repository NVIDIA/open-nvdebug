<template>
  <div class="nv-page">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
      <h2 class="nv-page__title">Redfish: {{ fileName }}</h2>
      <span class="nv-badge nv-badge--neutral">
        {{ resourceType }}
      </span>
      <span style="flex: 1;" />
      <button @click="showRaw = !showRaw" class="nv-btn">{{ showRaw ? 'Smart View' : 'Raw JSON' }}</button>
    </div>

    <PageLoader v-if="loading" message="Loading Redfish data..." />
    <div v-else-if="error" style="color: var(--nv-error);">{{ error }}</div>
    <template v-else>
      <!-- Raw JSON fallback -->
      <JsonTreeViewer v-if="showRaw || resourceType === 'unknown'" :content="content" height="calc(100vh - 200px)" />

      <!-- Specialized views -->
      <ThermalView v-else-if="resourceType === 'thermal'" :data="parsedData" />
      <EventLogTable v-else-if="resourceType === 'event-log'" :data="parsedData" />
      <SystemOverview v-else :data="parsedData" />
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { DataLoader } from '@/services/dataLoader'
import { detectRedfishType } from '@/composables/useRedfishDetector'
import JsonTreeViewer from '@/components/viewers/JsonTreeViewer.vue'
import ThermalView from '@/components/viewers/redfish/ThermalView.vue'
import EventLogTable from '@/components/viewers/redfish/EventLogTable.vue'
import SystemOverview from '@/components/viewers/redfish/SystemOverview.vue'
import PageLoader from '@/components/common/PageLoader.vue'

const route = useRoute()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()

const content = ref('')
const parsedData = ref<any>(null)
const loading = ref(false)
const error = ref('')
const showRaw = ref(false)

const filePath = computed(() => {
  // Build path from route params
  const dutId = route.params.dutId as string
  const collectorId = route.params.collectorId as string
  // Find the file in the manifest
  const files = manifestStore.fileIndex.filter(f =>
    f.dut_id === dutId && f.collector_id === collectorId && f.type === 'json'
  )
  return files[0]?.path ?? ''
})

const fileName = computed(() => filePath.value.split('/').pop() ?? '')
const resourceType = computed(() => parsedData.value ? detectRedfishType(parsedData.value) : 'unknown')

async function loadFile() {
  if (!filePath.value) return
  loading.value = true
  error.value = ''
  const loader = new DataLoader()
  if (fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded) {
    loader.setFileMap(fileSystemStore.fileMap)
  }
  const fileRef = manifestStore.fileIndex.find(f => f.path === filePath.value)
  if (!fileRef) { error.value = 'File not found'; loading.value = false; return }
  try {
    content.value = await loader.loadFile(fileRef)
    parsedData.value = JSON.parse(content.value)
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

watch(filePath, loadFile, { immediate: true })
</script>
