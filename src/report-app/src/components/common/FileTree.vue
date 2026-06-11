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

interface TreeNode {
  name: string
  path: string
  depth: number
  children?: TreeNode[]
  childCount?: number
  filePath?: string
  fileType?: string
  fileSize?: number
}

const props = defineProps<{
  files: FileEntry[]
  tree?: TreeNode[]
}>()

defineEmits<{
  'file-click': [path: string]
}>()

const expanded = ref(new Set<string>())

// Build tree from flat file list
const tree = computed<TreeNode[]>(() => {
  if (props.tree) return props.tree

  const root: Record<string, any> = {}
  for (const file of props.files) {
    const parts = file.path.split('/')
    let current = root
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]
      if (i === parts.length - 1) {
        // File leaf
        if (!current.__files__) current.__files__ = []
        current.__files__.push({ name: part, ...file })
      } else {
        if (!current[part]) current[part] = {}
        current = current[part]
      }
    }
  }

  function buildNodes(obj: Record<string, any>, parentPath: string, depth: number): TreeNode[] {
    const nodes: TreeNode[] = []

    // Folders first
    for (const [key, val] of Object.entries(obj).sort(([a], [b]) => a.localeCompare(b))) {
      if (key === '__files__') continue
      const path = parentPath ? `${parentPath}/${key}` : key
      const children = buildNodes(val, path, depth + 1)
      const fileCount = countFiles(val)
      nodes.push({ name: key, path, depth, children, childCount: fileCount })
    }

    // Then files
    if (obj.__files__) {
      for (const f of (obj.__files__ as any[]).sort((a: any, b: any) => a.name.localeCompare(b.name))) {
        nodes.push({ name: f.name, path: `${parentPath}/${f.name}`, depth, filePath: f.path, fileType: f.type, fileSize: f.size })
      }
    }

    return nodes
  }

  function countFiles(obj: Record<string, any>): number {
    let count = obj.__files__?.length ?? 0
    for (const [k, v] of Object.entries(obj)) {
      if (k !== '__files__' && typeof v === 'object') count += countFiles(v)
    }
    return count
  }

  return buildNodes(root, '', 0)
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
