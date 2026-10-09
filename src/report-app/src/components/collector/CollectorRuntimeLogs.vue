<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

<template>
  <section class="nv-card collector-runtime-logs" aria-labelledby="collector-runtime-logs-title">
    <div class="collector-runtime-logs__heading">
      <h3 id="collector-runtime-logs-title">Runtime Logs</h3>
      <router-link v-if="sourcePath" :to="`/file/${encodeURIComponent(sourcePath)}`" class="nv-btn nv-btn--sm">
        Open full node log
      </router-link>
    </div>
    <p class="collector-runtime-logs__description">
      Entries tagged for {{ collectorId }} on {{ dutId }}, including multiline details.
    </p>
    <p v-if="!sourcePath">This report does not include a runtime log for this node.</p>
    <div v-else-if="fileSystemStore.needsDirectoryPicker">
      <p>Select the report folder to view this collector’s runtime logs here.</p>
      <DirectoryPicker />
    </div>
    <p v-else-if="loading" role="status">
      Loading collector runtime logs… {{ formatBytes(bytesRead) }} scanned.
    </p>
    <div v-else-if="error" role="alert">
      <p>{{ error }}</p>
      <button type="button" class="nv-btn nv-btn--sm" @click="loadLogs">Retry runtime logs</button>
    </div>
    <template v-else-if="preview">
      <p v-if="preview.scanLimited || preview.previewLimited" role="status">
        Showing a partial log preview
        <template v-if="preview.scanLimited">after scanning {{ formatBytes(preview.bytesRead) }}</template>.
        Open the full node log to inspect additional entries.
      </p>
      <LogViewer v-if="preview.lineCount" :content="preview.content" height="360px" />
      <p v-else>
        No entries tagged for {{ collectorId }} were found{{ preview.scanLimited ? ' in the scanned portion' : '' }}.
        Untagged messages and formats without collector tags cannot be attributed to this collector.
      </p>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import { loadCollectorRuntimeLogs, type CollectorLogPreview } from '@/services/collectorRuntimeLogs'
import { formatBytes } from '@/utils/format'
import LogViewer from '@/components/viewers/LogViewer.vue'
import DirectoryPicker from '@/components/layout/DirectoryPicker.vue'

const props = defineProps<{ dutId: string; collectorId: string }>()
const manifestStore = useManifestStore()
const fileSystemStore = useFileSystemStore()
const sourcePath = computed(() => manifestStore.fileIndex.find(
  file => file.path === `${props.dutId}/nvdebug_runtime_output.txt`,
)?.path)
const preview = shallowRef<CollectorLogPreview | null>(null)
const loading = ref(false)
const bytesRead = ref(0)
const error = ref('')
let activeController: AbortController | null = null

async function loadLogs() {
  activeController?.abort()
  const controller = new AbortController()
  activeController = controller
  preview.value = null
  error.value = ''
  bytesRead.value = 0
  loading.value = false
  if (!sourcePath.value || fileSystemStore.needsDirectoryPicker) return

  loading.value = true
  const timeout = setTimeout(() => controller.abort(), 45_000)
  try {
    const result = await loadCollectorRuntimeLogs(sourcePath.value, props.collectorId, {
      mode: fileSystemStore.mode,
      fileMap: fileSystemStore.fileMap,
      signal: controller.signal,
      onProgress: bytes => {
        if (activeController === controller) bytesRead.value = bytes
      },
    })
    if (activeController === controller) preview.value = result
  } catch (cause) {
    if (activeController === controller) {
      error.value = controller.signal.aborted
        ? 'Loading the runtime log timed out. Retry to scan it again.'
        : cause instanceof Error ? cause.message : 'The runtime log could not be loaded.'
    }
  } finally {
    clearTimeout(timeout)
    if (activeController === controller) loading.value = false
  }
}

watch([
  sourcePath,
  () => props.collectorId,
  () => fileSystemStore.mode,
  () => fileSystemStore.directoryLoaded,
  () => fileSystemStore.fileMap.get(sourcePath.value ?? ''),
], loadLogs, { immediate: true })

onBeforeUnmount(() => {
  activeController?.abort()
  activeController = null
})
</script>

<style scoped>
.collector-runtime-logs { margin-bottom: 16px; min-width: 0; }
.collector-runtime-logs__heading { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
.collector-runtime-logs__heading h3 { margin: 0; font-size: 0.875rem; font-weight: 600; }
.collector-runtime-logs p { color: var(--nv-text-secondary); font-size: 0.8125rem; line-height: 1.5; }
.collector-runtime-logs__description { margin: 8px 0 12px; }
</style>
