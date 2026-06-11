<template>
  <div v-if="error" class="nv-card" style="border-color: var(--nv-error);">
    <p style="color: var(--nv-error); font-weight: 600; margin: 0 0 8px 0;">Something went wrong</p>
    <p style="color: var(--nv-text-secondary); font-size: 0.8125rem; margin: 0 0 12px 0;">{{ error.message }}</p>
    <button @click="retry" class="nv-btn nv-btn--primary">
      Retry
    </button>
  </div>
  <slot v-else />
</template>

<script setup lang="ts">
import { ref, onErrorCaptured } from 'vue'

const error = ref<Error | null>(null)

onErrorCaptured((err) => {
  error.value = err instanceof Error ? err : new Error(String(err))
  return false // prevent propagation
})

function retry() {
  error.value = null
}
</script>
