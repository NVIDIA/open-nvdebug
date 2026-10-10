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
  <div style="font-size: 0.8125rem;">
    <div
      v-for="node in tree"
      :key="node.path"
    >
      <!-- Folder -->
      <div
        v-if="node.children"
        @click="toggleFolder(node.path)"
        class="nv-sidebar__link"
        :style="{ paddingLeft: (node.depth * 16 + 8) + 'px' }"
      >
        <span>{{ expanded.has(node.path) ? '\uD83D\uDCC2' : '\uD83D\uDCC1' }}</span>
        <span>{{ node.name }}</span>
        <span style="color: var(--nv-text-secondary); font-size: 0.6875rem; margin-left: auto;">{{ node.childCount }}</span>
      </div>

      <!-- File -->
      <div
        v-else
        @click="$emit('file-click', node.filePath!)"
        class="nv-sidebar__link"
        :style="{ paddingLeft: (node.depth * 16 + 8) + 'px', fontSize: '12px' }"
      >
        <span>{{ fileIcon(node.fileType) }}</span>
        <span>{{ node.name }}</span>
        <span style="color: var(--nv-text-secondary); font-size: 0.6875rem; margin-left: auto;">{{ formatSize(node.fileSize) }}</span>
      </div>

      <!-- Recurse for children -->
      <template v-if="node.children && expanded.has(node.path)">
        <FileTree
          :files="[]"
          :tree="node.children"
          @file-click="(path: string) => $emit('file-click', path)"
        />
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import type { FileEntry } from '@/types/manifest'
import { buildFileTree, type FileTreeNode } from '@/utils/fileTree'

const props = defineProps<{
  files: FileEntry[]
  tree?: FileTreeNode[]
}>()

defineEmits<{
  'file-click': [path: string]
}>()

const expanded = ref(new Set<string>())

// Build tree from flat file list
const tree = computed<FileTreeNode[]>(() => {
  if (props.tree) return props.tree
  return buildFileTree(props.files)
})

// Expand top-level folders by default
onMounted(() => {
  for (const node of tree.value) {
    if (node.children) expanded.value.add(node.path)
  }
})

function toggleFolder(path: string) {
  if (expanded.value.has(path)) expanded.value.delete(path)
  else expanded.value.add(path)
}

function fileIcon(type?: string): string {
  switch (type) {
    case 'json': return '\uD83D\uDCC4'
    case 'log': return '\uD83D\uDCDD'
    case 'text': return '\uD83D\uDCC3'
    case 'xml': return '\uD83D\uDCCB'
    case 'yaml': return '\u2699\uFE0F'
    case 'binary': return '\uD83D\uDCBE'
    default: return '\uD83D\uDCC4'
  }
}

function formatSize(bytes?: number): string {
  if (!bytes) return ''
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}
</script>
