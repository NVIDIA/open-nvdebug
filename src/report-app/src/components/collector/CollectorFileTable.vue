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
  <DirectoryPicker v-if="fileSystemStore.needsDirectoryPicker" />
  <p v-if="downloadError" role="alert">{{ downloadError }}</p>
  <DataTable
    :columns="columns"
    :data="rows"
    :searchable="files.length > 5"
    :page-size="10"
    :state-key="stateKey"
    row-key="path"
  >
    <template #cell-name="{ row }">
      <span class="collector-file-name">{{ row.name }}</span>
    </template>
    <template #cell-formattedDuration="{ row }">
      <div class="collector-file-timing">
        <span class="collector-file-duration">{{ row.formattedDuration }}</span>
        <span v-if="row.sharedTiming" class="collector-file-attribution">{{ row.attribution }}</span>
        <button
          v-if="row.hasTiming"
          type="button"
          class="nv-btn nv-btn--view nv-btn--row-action"
          :aria-label="`Timing details for ${row.name}`"
          @click="selectedPath = row.path"
        >
          Timing details
        </button>
      </div>
    </template>
    <template #cell-type="{ value }">
      <span :class="['nv-badge', typeBadgeClass(value)]">{{ value }}</span>
    </template>
    <template #cell-size="{ value }">
      <span class="collector-file-size">{{ formatBytes(value) }}</span>
    </template>
    <template #cell-actions="{ row }">
      <div class="collector-file-actions">
        <router-link
          :to="`/file/${encodeURIComponent(row.path)}`"
          class="nv-btn nv-btn--view nv-btn--row-action"
          :aria-label="`Open ${row.name}`"
        >
          Open <span aria-hidden="true">&rarr;</span>
        </router-link>
        <a
          v-if="fileSystemStore.mode === 'http' && row.downloadUrl"
          :href="row.downloadUrl"
          :download="row.name"
          class="nv-btn nv-btn--primary nv-btn--row-action"
          :aria-label="`Download ${row.name}`"
        >
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 1v9M4 7l4 4 4-4M2 12v2h12v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>
          Download
        </a>
        <button
          v-else
          type="button"
          class="nv-btn nv-btn--primary nv-btn--row-action"
          :disabled="fileSystemStore.mode !== 'file' || !fileSystemStore.getFile(row.path)"
          :title="downloadUnavailableReason(row.path)"
          :aria-label="`Download ${row.name}`"
          @click="downloadOfflineFile(row.path)"
        >
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 1v9M4 7l4 4 4-4M2 12v2h12v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>
          Download
        </button>
      </div>
      <span v-if="fileSystemStore.mode === 'file' && fileSystemStore.directoryLoaded && !fileSystemStore.getFile(row.path)" class="collector-file-missing">
        Missing from selected folder
      </span>
    </template>
  </DataTable>
  <Teleport to="body">
    <dialog
      ref="timingDialog"
      class="collector-file-dialog"
      :aria-labelledby="dialogTitleId"
      @cancel.prevent="closeTiming"
      @close="onDialogClose"
      @click.self="closeTiming"
      @keydown.stop="onDialogKeydown"
    >
      <template v-if="selectedFile">
        <div class="nv-modal__header">
          <h3 :id="dialogTitleId" class="nv-modal__title">File timing details</h3>
          <button type="button" class="nv-modal__close" aria-label="Close file timing details" autofocus @click="closeTiming">&times;</button>
        </div>
        <div class="nv-modal__body">
          <p class="collector-file-dialog__name">{{ selectedFile.name }}</p>
          <p v-if="selectedFile.sharedTiming" class="collector-file-dialog__note">
            This timing covers {{ selectedFile.attribution.toLowerCase() }}. It is not an individual file transfer duration.
          </p>
          <dl class="collector-file-dialog__fields">
            <div><dt>Duration</dt><dd>{{ selectedFile.formattedDuration }}</dd></div>
            <div><dt>Attribution</dt><dd>{{ selectedFile.attribution }}</dd></div>
            <div><dt>Source</dt><dd>{{ selectedFile.measurement?.replace(/_/g, ' ') || 'Not recorded' }}</dd></div>
            <div><dt>Quality</dt><dd>{{ selectedFile.measurement_quality?.replace(/_/g, ' ') || 'Not recorded' }}</dd></div>
            <div><dt>Started</dt><dd>{{ selectedFile.started_at || 'Not recorded' }}</dd></div>
            <div><dt>Ended</dt><dd>{{ selectedFile.ended_at || 'Not recorded' }}</dd></div>
            <div v-if="selectedFile.produced_by_operation_id" class="collector-file-dialog__operation"><dt>Operation</dt><dd>{{ selectedFile.produced_by_operation_id }}</dd></div>
          </dl>
          <button type="button" class="nv-btn nv-btn--view" @click="showOperationTiming">View operation timing <span aria-hidden="true">&rarr;</span></button>
        </div>
      </template>
    </dialog>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, useId, watch } from 'vue'
import DataTable from '@/components/common/DataTable.vue'
import DirectoryPicker from '@/components/layout/DirectoryPicker.vue'
import { reportArtifactUrl, useFileSystemStore } from '@/stores/fileSystem'
import { formatBytes, formatDuration } from '@/utils/format'
import type { FileRef } from '@/types/manifest'

const props = defineProps<{ files: FileRef[]; stateKey: string }>()
const emit = defineEmits<{ 'show-operation-timing': [] }>()
const fileSystemStore = useFileSystemStore()
const downloadError = ref('')
const selectedPath = ref<string | null>(null)
const timingDialog = ref<HTMLDialogElement | null>(null)
const dialogTitleId = useId()
const columns = [
  { key: 'name', label: 'File Name', sortable: true },
  { key: 'type', label: 'Type', sortable: true },
  { key: 'size', label: 'Size', sortable: true },
  { key: 'formattedDuration', label: 'Timing', sortable: false },
  { key: 'actions', label: 'Actions', sortable: false },
]
const rows = computed(() => props.files.map(file => ({
  ...file,
  name: file.path.split('/').pop() || file.path,
  attribution: attribution(file),
  formattedDuration: artifactDuration(file),
  sharedTiming: file.measurement_scope === 'shared_operation' || file.measurement_scope === 'shared_requests',
  hasTiming: typeof file.duration_seconds === 'number' && Number.isFinite(file.duration_seconds) || Boolean(
    file.measurement || file.measurement_scope || file.measurement_quality || file.produced_by_operation_id || file.started_at || file.ended_at,
  ),
  downloadUrl: fileSystemStore.mode === 'http' ? reportArtifactUrl(file.path)?.href : undefined,
})))
const selectedFile = computed(() => rows.value.find(file => file.path === selectedPath.value))

watch(selectedFile, async () => {
  await nextTick()
  const dialog = timingDialog.value
  if (!dialog) return
  if (selectedFile.value && !dialog.open) dialog.showModal()
  else if (!selectedFile.value && dialog.open) dialog.close()
})

function closeTiming() {
  timingDialog.value?.close()
  selectedPath.value = null
}

function onDialogClose() {
  // Native close events are queued and may arrive after the user reopens the dialog.
  if (!timingDialog.value?.open) selectedPath.value = null
}

function onDialogKeydown(event: KeyboardEvent) {
  if (event.key !== 'Tab') return
  const buttons = timingDialog.value?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')
  if (!buttons?.length) return
  const first = buttons[0]
  const last = buttons[buttons.length - 1]
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

function showOperationTiming() {
  closeTiming()
  emit('show-operation-timing')
}

onBeforeUnmount(() => {
  if (timingDialog.value?.open) timingDialog.value.close()
})

function typeBadgeClass(type: string): string {
  const classes: Record<string, string> = {
    json: 'nv-badge--info', xml: 'nv-badge--info', yaml: 'nv-badge--info', binary: 'nv-badge--warning',
  }
  return classes[type] ?? 'nv-badge--neutral'
}

function attribution(file: FileRef): string {
  if (file.measurement_scope === 'shared_operation') {
    return `Shared operation (${file.shared_operation_artifact_count ?? '?'} files)`
  }
  if (file.measurement_scope === 'shared_requests') {
    return `Shared requests (${file.shared_request_operation_count ?? '?'} requests)`
  }
  return file.measurement_scope?.replace(/_/g, ' ') || '—'
}

function artifactDuration(file: FileRef): string {
  if (typeof file.duration_seconds === 'number' && Number.isFinite(file.duration_seconds)) {
    return formatDuration(file.duration_seconds)
  }
  if (file.measurement_scope === 'shared_operation' || file.measurement_scope === 'shared_requests') {
    return 'Shared timing'
  }
  return 'Not recorded'
}

function downloadUnavailableReason(path: string): string {
  if (fileSystemStore.mode !== 'file') return 'The report contains an invalid file path.'
  if (fileSystemStore.needsDirectoryPicker) return 'Select the report folder to download this file.'
  return fileSystemStore.getFile(path) ? '' : 'This file is missing from the selected folder.'
}

function downloadOfflineFile(path: string) {
  downloadError.value = ''
  const file = fileSystemStore.getFile(path)
  if (!file) {
    downloadError.value = downloadUnavailableReason(path)
    return
  }
  let url = ''
  try {
    // Keep the original File bytes; do not decode or buffer large/binary artifacts.
    url = URL.createObjectURL(file)
    const link = document.createElement('a')
    link.href = url
    link.download = path.split('/').pop() || file.name
    link.click()
  } catch {
    downloadError.value = 'The file could not be downloaded. Try opening it from the selected folder.'
  } finally {
    if (url) setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}
</script>

<style scoped>
.collector-file-name { display: block; min-width: 150px; font-weight: 500; overflow-wrap: anywhere; }
.collector-file-size { font-family: var(--nv-font-mono); white-space: nowrap; }
.collector-file-actions { display: flex; flex-wrap: wrap; gap: 6px; }
.collector-file-missing { display: block; margin-top: 4px; color: var(--nv-text-secondary); font-size: 0.75rem; }
.collector-file-timing { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; min-width: 130px; font-size: 0.75rem; }
.collector-file-duration { font-weight: 600; }
.collector-file-attribution { color: var(--nv-text-secondary); }
.collector-file-dialog {
  margin: auto;
  padding: 0;
  width: min(720px, calc(100vw - 32px));
  max-height: calc(100dvh - 32px);
  overflow: auto;
  color: var(--nv-text-primary);
  background: var(--nv-bg-elevated);
  border: 1px solid var(--nv-border-strong);
  border-radius: var(--nv-radius-xl);
  box-shadow: var(--nv-glass-shadow-elevated);
}
.collector-file-dialog::backdrop { background: rgba(0, 0, 0, 0.6); }
.collector-file-dialog__name { font-family: var(--nv-font-mono); overflow-wrap: anywhere; margin-bottom: 16px; }
.collector-file-dialog__note { padding: 12px; border-radius: var(--nv-radius-md); background: var(--nv-info-muted); margin-bottom: 16px; }
.collector-file-dialog__fields { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
.collector-file-dialog__fields dt { color: var(--nv-text-secondary); font-size: 0.75rem; margin-bottom: 4px; }
.collector-file-dialog__fields dd { margin: 0; overflow-wrap: anywhere; }
.collector-file-dialog__operation { grid-column: 1 / -1; }
@media (max-width: 600px) {
  .collector-file-dialog__fields { grid-template-columns: 1fr; }
}
</style>
