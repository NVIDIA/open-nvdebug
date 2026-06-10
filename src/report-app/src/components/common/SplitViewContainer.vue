<template>
  <div v-if="active" style="display: flex; height: 100%; gap: 2px;">
    <div style="flex: 1; overflow: auto; border-right: 2px solid var(--nv-accent);">
      <slot name="left" />
    </div>
    <div style="flex: 1; overflow: auto;">
      <slot name="right" />
    </div>
  </div>
  <div v-else style="height: 100%;">
    <slot name="left" />
  </div>
</template>

<script setup lang="ts">
defineProps<{
  active: boolean
}>()
</script>
