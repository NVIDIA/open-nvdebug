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
  <div class="nv-log">
    <!-- Filter Bar -->
    <div class="nv-log__toolbar">
      <input
        v-model="searchText"
        type="text"
        placeholder="Search logs..."
        aria-label="Search logs"
        class="nv-input nv-input--sm"
        style="width: 200px;"
      />
      <select v-model="levelFilter" aria-label="Log level" class="nv-select nv-select--sm">
        <option value="">All Levels</option>
        <option v-for="level in levels" :key="level" :value="level">{{ level }}</option>
      </select>
      <select v-model="componentFilter" aria-label="Log component" class="nv-select nv-select--sm">
        <option value="">All Components</option>
        <option v-for="comp in components" :key="comp" :value="comp">{{ comp }}</option>
      </select>
      <span class="nv-log__count">
        {{ visibleLines.length }} / {{ parsedLines.length }} lines
      </span>
      <button @click="copyFiltered" class="nv-btn nv-btn--sm" title="Copy filtered">Copy</button>
      <button @click="downloadFiltered" class="nv-btn nv-btn--primary nv-btn--row-action" title="Download filtered">
        <svg aria-hidden="true" width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8 1v9M4 7l4 4 4-4M2 12v2h12v-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>
        Download
      </button>
    </div>

    <div v-if="preview.truncated" class="nv-log__preview-notice" role="status">
      {{ previewNotice }} Download the original file to inspect omitted content.
    </div>

    <!-- Log Content -->
    <div
      ref="logContainer"
      class="nv-log__content"
      :style="{ height: height }"
    >
      <div
        v-for="(line, i) in visibleLines"
        :key="i"
        :class="['nv-log__line', levelClass(line.level)]"
      >
        <span v-if="line.timestamp" class="nv-log__timestamp">[{{ line.timestamp }}] </span>
        <span v-if="line.level" :class="['nv-log__level', levelLabelClass(line.level)]">[{{ line.level }}] </span>
        <span v-if="line.collectorId" class="nv-log__component">[CID:{{ line.collectorId }}] </span>
        <span v-if="line.component" class="nv-log__component">[{{ line.component }}] </span>
        <span class="nv-log__message">{{ line.message }}</span>
      </div>
      <div v-if="visibleLines.length === 0" class="nv-empty">
        No matching log lines
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { showToast } from '@/composables/useToast'
import { copyToClipboard } from '@/utils/clipboard'
import { parseLogPreview } from '@/utils/logLines'

const props = withDefaults(defineProps<{
  content: string
  height?: string
}>(), {
  height: '500px',
})

const searchText = ref('')
const levelFilter = ref('')
const componentFilter = ref('')
const logContainer = ref<HTMLElement>()

const preview = computed(() => parseLogPreview(props.content))
const parsedLines = computed(() => preview.value.lines)
const previewNotice = computed(() => {
  const details: string[] = []
  if (preview.value.omittedCharacters > 0) {
    details.push(`${preview.value.omittedCharacters.toLocaleString()} characters omitted`)
  }
  if (preview.value.truncatedLineCount > 0) {
    details.push(`${preview.value.truncatedLineCount.toLocaleString()} long lines truncated`)
  }
  return `Bounded log preview: ${details.join('; ')}.`
})

const levels = computed(() => [...new Set(parsedLines.value.map(l => l.level).filter(Boolean))].sort() as string[])
const components = computed(() => [...new Set(parsedLines.value.map(l => l.component).filter(Boolean))].sort() as string[])

const visibleLines = computed(() => {
  return parsedLines.value.filter(line => {
    if (levelFilter.value && line.level !== levelFilter.value) return false
    if (componentFilter.value && line.component !== componentFilter.value) return false
    if (searchText.value && !line.raw.toLowerCase().includes(searchText.value.toLowerCase())) return false
    return true
  })
})

function levelClass(level: string | null): string {
  switch (level) {
    case 'ERROR': return 'nv-log__line--error'
    case 'WARNING': return 'nv-log__line--warning'
    case 'INFO': return 'nv-log__line--info'
    case 'DEBUG': return 'nv-log__line--debug'
    default: return ''
  }
}

function levelLabelClass(level: string | null): string {
  switch (level) {
    case 'ERROR': return 'nv-log__level--error'
    case 'WARNING': return 'nv-log__level--warning'
    case 'INFO': return 'nv-log__level--info'
    case 'DEBUG': return 'nv-log__level--debug'
    default: return ''
  }
}

function copyFiltered() {
  const text = visibleLines.value.map(l => l.raw).join('\n')
  copyToClipboard(text).then(
    () => showToast(`Copied ${visibleLines.value.length} lines`, 'success'),
    () => showToast('Failed to copy', 'error'),
  )
}

function downloadFiltered() {
  const text = visibleLines.value.map(l => l.raw).join('\n')
  const blob = new Blob([text], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'filtered_log.txt'
  a.click()
  URL.revokeObjectURL(url)
  showToast('Download started', 'success')
}
</script>
