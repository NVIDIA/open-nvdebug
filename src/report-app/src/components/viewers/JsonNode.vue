<template>
  <div>
    <!-- Object/Array -->
    <div
      v-if="isExpandable"
      :data-json-path="path"
      :style="{ marginLeft: (depth * 16) + 'px' }"
      @contextmenu.prevent="onContext($event)"
    >
      <span @click="$emit('toggle', path)" style="cursor: pointer; user-select: none;">
        <span class="nv-json-node__toggle">{{ isExpanded ? '\u25BC' : '\u25B6' }}</span>
        <span v-if="label" class="nv-json-node__key">{{ label }}</span>
        <span class="nv-json-node__bracket"> {{ bracketLabel }}</span>
      </span>

      <div v-if="isExpanded">
        <JsonNode
          v-for="(val, key) in entries"
          :key="String(key)"
          :data="val"
          :label="String(key)"
          :path="`${path}.${key}`"
          :depth="depth + 1"
          :search="search"
          :expanded-paths="expandedPaths"
          @toggle="(p: string) => $emit('toggle', p)"
          @contextmenu-node="(e: any) => $emit('contextmenu-node', e)"
          @match-paths="(paths: string[]) => $emit('match-paths', paths)"
        />
      </div>
    </div>

    <!-- Primitive -->
    <div
      v-else
      :data-json-path="path"
      :style="{ marginLeft: (depth * 16) + 'px', padding: '1px 0' }"
      @contextmenu.prevent="onContext($event)"
    >
      <span v-if="label" class="nv-json-node__key">{{ label }}: </span>
      <span
        :style="{ color: valueColor }"
        :class="{ 'nv-json-node__search-match': isSearchMatch }"
        :data-match-path="isSearchMatch ? path : undefined"
      >{{ displayValue }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  data: any
  path: string
  depth: number
  search: string
  expandedPaths: Set<string>
  label?: string
}>()

const emit = defineEmits<{
  toggle: [path: string]
  'contextmenu-node': [payload: { event: MouseEvent; path: string; key: string; data: any; isExpandable: boolean }]
  'match-paths': [paths: string[]]
}>()

const isExpandable = computed(() => props.data !== null && typeof props.data === 'object')
const isArray = computed(() => Array.isArray(props.data))
const isExpanded = computed(() => props.expandedPaths.has(props.path))
const bracketLabel = computed(() => isArray.value ? `[${dataLength.value}]` : '{' + dataLength.value + '}')
const dataLength = computed(() => isExpandable.value ? Object.keys(props.data).length : 0)
const entries = computed(() => isExpandable.value ? props.data : {})

const displayValue = computed(() => {
  if (props.data === null) return 'null'
  if (typeof props.data === 'string') return `"${props.data}"`
  return String(props.data)
})

const valueColor = computed(() => {
  if (props.data === null) return 'var(--nv-text-tertiary)'
  if (typeof props.data === 'string') return 'var(--nv-error)'
  if (typeof props.data === 'number') return 'var(--nv-info)'
  if (typeof props.data === 'boolean') return 'var(--nv-chart-purple)'
  return 'var(--nv-text-primary)'
})

const isSearchMatch = computed(() => {
  if (!props.search) return false
  const q = props.search.toLowerCase()
  return displayValue.value.toLowerCase().includes(q) ||
    (props.label?.toLowerCase().includes(q) ?? false)
})

function onContext(event: MouseEvent) {
  emit('contextmenu-node', {
    event,
    path: props.path,
    key: props.label ?? '',
    data: props.data,
    isExpandable: isExpandable.value,
  })
}
</script>
