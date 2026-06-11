<template>
  <div>
    <!-- Trigger button -->
    <button @click="open = true" class="nv-btn nv-btn--ghost nv-btn--sm" style="position: absolute; top: 4px; right: 4px; z-index: 1;" title="Fullscreen">
      &#x26F6;
    </button>

    <!-- Fullscreen modal -->
    <Teleport to="body">
      <div v-if="open" @click.self="open = false" @keydown.escape="open = false" tabindex="-1" ref="overlayRef"
        class="nv-modal-overlay">
        <div class="nv-modal nv-modal--fullscreen" @click.stop>
          <div class="nv-modal__header">
            <h3 v-if="title" class="nv-modal__title">{{ title }}</h3>
            <button @click="open = false" class="nv-modal__close">&times;</button>
          </div>
          <div class="nv-modal__body" style="height: calc(100% - 65px);">
            <slot name="fullscreen" />
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Normal view -->
    <div style="position: relative;">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, nextTick } from 'vue'

defineProps<{
  title?: string
}>()

const open = ref(false)
const overlayRef = ref<HTMLElement>()

watch(open, async (val) => {
  if (val) {
    await nextTick()
    overlayRef.value?.focus()
  }
})
</script>
