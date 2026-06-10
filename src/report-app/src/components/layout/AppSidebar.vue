<template>
  <aside
    v-if="visible"
    :class="['nv-sidebar', isMobile && 'nv-sidebar--mobile']"
  >
    <slot />
  </aside>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  visible: boolean
  isMobile: boolean
}>()
</script>
