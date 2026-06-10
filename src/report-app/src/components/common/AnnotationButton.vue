<template>
  <span>
    <button @click="showEditor = !showEditor" :class="['nv-btn', 'nv-btn--ghost', 'nv-btn--sm']" :title="hasNote ? 'Edit note' : 'Add note'">
      {{ hasNote ? '\uD83D\uDCDD' : '\u270F\uFE0F' }}
    </button>

    <!-- Inline editor -->
    <div v-if="showEditor" class="nv-card nv-card--elevated" style="position: absolute; z-index: 100; width: 300px; padding: 12px;">
      <textarea
        v-model="noteText"
        placeholder="Add a note..."
        rows="3"
        class="nv-input"
        style="resize: vertical;"
      ></textarea>
      <div style="display: flex; gap: 6px; margin-top: 8px;">
        <button @click="saveNote" class="nv-btn nv-btn--primary nv-btn--sm">Save</button>
        <button v-if="hasNote" @click="deleteNote" class="nv-btn nv-btn--danger nv-btn--sm">Delete</button>
        <button @click="showEditor = false" class="nv-btn nv-btn--sm">Cancel</button>
      </div>
    </div>
  </span>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useAnnotationsStore } from '@/stores/annotations'

const props = defineProps<{
  itemPath: string
  itemLabel: string
}>()

const store = useAnnotationsStore()
const showEditor = ref(false)
const noteText = ref('')

const hasNote = computed(() => store.hasAnnotation(props.itemPath))

watch(showEditor, (open) => {
  if (open) {
    const existing = store.getAnnotation(props.itemPath)
    noteText.value = existing?.text ?? ''
  }
})

function saveNote() {
  if (noteText.value.trim()) {
    store.addAnnotation(props.itemPath, props.itemLabel, noteText.value.trim())
  }
  showEditor.value = false
}

function deleteNote() {
  store.removeAnnotation(props.itemPath)
  showEditor.value = false
}
</script>
