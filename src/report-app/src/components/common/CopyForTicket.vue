<template>
  <button @click="copy" class="nv-btn nv-btn--sm" :title="title">
    {{ copied ? 'Copied!' : label }}
  </button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { copyToClipboard } from '@/composables/useCopyForTicket'

const props = withDefaults(defineProps<{
  text: string
  label?: string
  title?: string
}>(), {
  label: 'Copy for Ticket',
  title: 'Copy formatted text to clipboard',
})

const copied = ref(false)

async function copy() {
  const success = await copyToClipboard(props.text)
  if (success) {
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  }
}
</script>
