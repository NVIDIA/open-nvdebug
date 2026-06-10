<template>
  <div v-if="visible" class="nv-card nv-card--elevated" :style="{
    position: 'fixed', left: x + 'px', top: y + 'px', zIndex: 1000,
    padding: '8px 0', minWidth: '180px',
  }" @click.stop>
    <div class="nv-sidebar__section-title" style="padding: 4px 12px 8px;">
      Columns
    </div>
    <label
      v-for="col in allColumns"
      :key="col.key"
      style="display: flex; align-items: center; gap: 8px; padding: 4px 12px; cursor: pointer; font-size: 0.8125rem; color: var(--nv-text-primary);"
    >
      <input type="checkbox" :checked="visibleColumns.has(col.key)" @change="toggle(col.key)" />
      {{ col.label }}
    </label>
    <div style="border-top: 1px solid var(--nv-border); margin-top: 4px; padding-top: 4px;">
      <button @click="resetAll" class="nv-btn nv-btn--ghost nv-btn--sm" style="display: block; width: 100%; text-align: left; padding: 4px 12px;">
        Reset to Default
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'

interface ColumnDef {
  key: string
  label: string
}

const props = defineProps<{
  allColumns: ColumnDef[]
  storageKey: string
}>()

const emit = defineEmits<{
  'update:visible-columns': [columns: Set<string>]
}>()

const visible = ref(false)
const x = ref(0)
const y = ref(0)
const visibleColumns = reactive(new Set<string>())

function show(event: MouseEvent) {
  x.value = event.clientX
  y.value = event.clientY
  visible.value = true
}

function hide() {
  visible.value = false
}

function toggle(key: string) {
  if (visibleColumns.has(key)) visibleColumns.delete(key)
  else visibleColumns.add(key)
  save()
  emit('update:visible-columns', visibleColumns)
}

function resetAll() {
  visibleColumns.clear()
  for (const col of props.allColumns) visibleColumns.add(col.key)
  save()
  emit('update:visible-columns', visibleColumns)
}

function save() {
  localStorage.setItem(`nv-columns-${props.storageKey}`, JSON.stringify([...visibleColumns]))
}

function load() {
  try {
    const saved = localStorage.getItem(`nv-columns-${props.storageKey}`)
    if (saved) {
      const keys = JSON.parse(saved) as string[]
      visibleColumns.clear()
      for (const k of keys) visibleColumns.add(k)
    } else {
      resetAll()
    }
  } catch {
    resetAll()
  }
}

function onGlobalClick() { visible.value = false }

onMounted(() => {
  load()
  document.addEventListener('click', onGlobalClick)
})
onUnmounted(() => document.removeEventListener('click', onGlobalClick))

defineExpose({ show, hide, visibleColumns })
</script>
