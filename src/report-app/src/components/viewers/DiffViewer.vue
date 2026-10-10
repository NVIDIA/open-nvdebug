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
    <div class="nv-log__toolbar">
      <span style="font-size: 0.8125rem; color: var(--nv-text-primary); font-weight: 600;">Diff View</span>
      <span style="flex: 1;" />
      <button @click="inline = !inline" class="nv-btn nv-btn--sm">
        {{ inline ? 'Side by Side' : 'Inline' }}
      </button>
    </div>
    <div ref="diffContainer" :style="{ height }"></div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import * as monaco from 'monaco-editor'
import { useThemeStore } from '@/stores/theme'
import { useThemeColors } from '@/composables/useThemeColors'
import { toHex6 } from '@/utils/color'

const props = withDefaults(defineProps<{
  original: string
  modified: string
  language?: string
  height?: string
}>(), {
  language: 'plaintext',
  height: '500px',
})

const diffContainer = ref<HTMLElement>()
const inline = ref(false)
const themeStore = useThemeStore()
let diffEditor: monaco.editor.IStandaloneDiffEditor | null = null

function defineNvThemes() {
  const colors = useThemeColors()
  const accent = toHex6(colors.accent, '#76B900')
  monaco.editor.defineTheme('nv-light', {
    base: 'vs', inherit: true, rules: [],
    colors: {
      'editor.background': '#FFFFFF',
      'editor.foreground': toHex6(colors.textPrimary, '#1A1A1A'),
      'editorLineNumber.foreground': toHex6(colors.textTertiary, '#616161'),
      'editor.selectionBackground': accent + '33',
    },
  })
  monaco.editor.defineTheme('nv-dark', {
    base: 'vs-dark', inherit: true, rules: [],
    colors: {
      'editor.background': toHex6(colors.bgElevated, '#2C2C2C'),
      'editor.foreground': toHex6(colors.textPrimary, '#E0E0E0'),
      'editorLineNumber.foreground': toHex6(colors.textSecondary, '#9E9E9E'),
      'editor.selectionBackground': accent + '33',
    },
  })
}

onMounted(() => {
  if (!diffContainer.value) return

  defineNvThemes()

  diffEditor = monaco.editor.createDiffEditor(diffContainer.value, {
    theme: themeStore.theme === 'dark' ? 'nv-dark' : 'nv-light',
    readOnly: true,
    renderSideBySide: !inline.value,
    automaticLayout: true,
    fontSize: 13,
    scrollBeyondLastLine: false,
  })

  diffEditor.setModel({
    original: monaco.editor.createModel(props.original, props.language),
    modified: monaco.editor.createModel(props.modified, props.language),
  })
})

watch(inline, (val) => {
  diffEditor?.updateOptions({ renderSideBySide: !val })
})

watch(() => themeStore.theme, () => {
  defineNvThemes()
  monaco.editor.setTheme(themeStore.theme === 'dark' ? 'nv-dark' : 'nv-light')
})

onUnmounted(() => {
  if (diffEditor) {
    const model = diffEditor.getModel()
    model?.original?.dispose()
    model?.modified?.dispose()
    diffEditor.dispose()
    diffEditor = null
  }
})
</script>
