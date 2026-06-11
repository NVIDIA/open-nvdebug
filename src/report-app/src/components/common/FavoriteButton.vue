<template>
  <button
    @click="store.toggleFavorite(itemPath)"
    :class="['nv-btn', 'nv-btn--ghost', 'nv-btn--sm']"
    :title="isFav ? 'Remove from favorites' : 'Add to favorites'"
  >
    {{ isFav ? '\u2605' : '\u2606' }}
  </button>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useAnnotationsStore } from '@/stores/annotations'

const props = defineProps<{ itemPath: string }>()
const store = useAnnotationsStore()
const isFav = computed(() => store.isFavorite(props.itemPath))
</script>
