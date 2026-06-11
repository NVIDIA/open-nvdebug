<template>
  <Teleport to="body">
    <div v-if="open" @click.self="close" @keydown.escape="close" tabindex="-1" ref="overlayRef"
      class="nv-modal-overlay">
      <div class="nv-modal nv-modal--sm">
        <div class="nv-modal__header">
          <h2 class="nv-modal__title">Keyboard Shortcuts</h2>
          <button @click="close" class="nv-modal__close">&times;</button>
        </div>

        <div class="nv-modal__body">
          <div v-for="group in shortcutGroups" :key="group.title" style="margin-bottom: 16px;">
            <h3 class="nv-section-subtitle">{{ group.title }}</h3>
            <div v-for="s in group.shortcuts" :key="s.keys" style="display: flex; justify-content: space-between; padding: 4px 0; font-size: 0.8125rem;">
              <span style="color: var(--nv-text-primary);">{{ s.description }}</span>
              <kbd>{{ s.keys }}</kbd>
            </div>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, nextTick } from 'vue'

const open = ref(false)
const overlayRef = ref<HTMLElement>()

const shortcutGroups = [
  {
    title: 'Navigation',
    shortcuts: [
      { keys: 'Ctrl+K', description: 'Command palette' },
      { keys: 'Ctrl+P', description: 'Quick file open' },
      { keys: 'Ctrl+Shift+F', description: 'Cross-file search' },
      { keys: '[ / ]', description: 'Previous / next file' },
    ],
  },
  {
    title: 'View',
    shortcuts: [
      { keys: 'Ctrl+\\', description: 'Toggle split view' },
      { keys: 't', description: 'Toggle theme' },
      { keys: 's', description: 'Star/unstar current item' },
    ],
  },
  {
    title: 'Search',
    shortcuts: [
      { keys: 'Ctrl+F', description: 'Search in current viewer' },
      { keys: 'Escape', description: 'Close modal / palette' },
    ],
  },
  {
    title: 'Help',
    shortcuts: [
      { keys: '?', description: 'Show this help' },
    ],
  },
]

function show() {
  open.value = true
  nextTick(() => overlayRef.value?.focus())
}

function close() { open.value = false }

defineExpose({ show, close })
</script>
