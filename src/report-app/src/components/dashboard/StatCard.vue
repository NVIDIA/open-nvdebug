<template>
  <div
    @click="$emit('click')"
    :class="['nv-stat', `nv-stat--${color}`, clickable && 'nv-stat--clickable']"
  >
    <div class="nv-stat__label">{{ label }}</div>
    <div class="nv-stat__value">{{ value }}</div>
    <div v-if="subtitle" class="nv-stat__subtitle">{{ subtitle }}</div>
  </div>
</template>

<script setup lang="ts">
const props = withDefaults(defineProps<{
  label: string
  value: string | number
  subtitle?: string
  color?: string
  gradient?: string
  clickable?: boolean
}>(), {
  color: 'green',
  clickable: false,
})

defineEmits<{ click: [] }>()
</script>
