<template>
  <button @click="copy" :class="['nv-btn', 'nv-btn--ghost', 'nv-btn--sm']" :title="copied ? 'Copied!' : 'Copy'">
    {{ copied ? '\u2713' : '\uD83D\uDCCB' }}
  </button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { copyToClipboard } from '@/utils/clipboard'

const props = defineProps<{ text: string }>()
const copied = ref(false)

async function copy() {
  try {
    await copyToClipboard(props.text)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch { /* ignore */ }
}
</script>
