<template>
  <div :class="['nv-callout', `nv-callout--${variant}`]" role="note">
    <div v-if="title" class="nv-callout__title">{{ title }}</div>
    <slot />
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  variant?: 'info' | 'success' | 'warning' | 'danger'
  title?: string
}>(), {
  variant: 'info',
})
</script>
