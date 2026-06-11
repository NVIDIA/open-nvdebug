<template>
  <div class="nv-page">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
      <h2 class="nv-page__title">Notes ({{ store.annotations.length }})</h2>
      <span style="flex: 1;" />
      <button @click="exportNotes" class="nv-btn nv-btn--sm">Export</button>
      <label class="nv-btn nv-btn--sm" style="cursor: pointer;">
        Import
        <input type="file" accept=".json" style="display: none;" @change="importNotes" />
      </label>
    </div>

    <div v-if="store.annotations.length === 0" class="nv-empty">
      No notes yet. Click the pencil icon on any item to add a note.
    </div>

    <div v-for="note in store.annotations" :key="note.id" class="nv-card" style="margin-bottom: 8px;">
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
        <router-link :to="note.itemPath" style="font-size: 0.8125rem; font-weight: 600;">{{ note.itemLabel }}</router-link>
        <span style="font-size: 0.6875rem; color: var(--nv-text-secondary);">{{ new Date(note.createdAt).toLocaleString() }}</span>
        <span style="flex: 1;" />
        <button @click="store.removeAnnotation(note.itemPath)" class="nv-btn nv-btn--ghost nv-btn--sm">&#10005;</button>
      </div>
      <div style="font-size: 0.8125rem; color: var(--nv-text-primary); white-space: pre-wrap;">{{ note.text }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useAnnotationsStore } from '@/stores/annotations'

const store = useAnnotationsStore()

function exportNotes() {
  const json = store.exportJson()
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'report-notes.json'
  a.click()
  URL.revokeObjectURL(url)
}

function importNotes(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    if (typeof reader.result === 'string') store.importJson(reader.result)
  }
  reader.readAsText(file)
}
</script>
