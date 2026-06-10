<template>
  <div class="empty-state">
    <div class="empty-state__icon">
      <!-- search -->
      <svg v-if="icon === 'search'" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      <!-- data -->
      <svg v-else-if="icon === 'data'" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/>
      </svg>
      <!-- error -->
      <svg v-else-if="icon === 'error'" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/>
      </svg>
      <!-- file -->
      <svg v-else width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6"/><path d="m9 15 3-3 3 3"/>
      </svg>
    </div>
    <h3 class="empty-state__title">{{ title }}</h3>
    <p v-if="description" class="empty-state__desc">{{ description }}</p>
    <div v-if="$slots.default" class="empty-state__action">
      <slot />
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  icon?: 'search' | 'data' | 'error' | 'file'
  title: string
  description?: string
}>()
</script>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  text-align: center;
  gap: 12px;
}
.empty-state__icon {
  color: var(--nv-text-tertiary, rgba(255,255,255,0.3));
  margin-bottom: 4px;
}
.empty-state__title {
  margin: 0;
  font-size: 0.9375rem;
  font-weight: 600;
  color: var(--nv-text-secondary, rgba(255,255,255,0.7));
}
.empty-state__desc {
  margin: 0;
  font-size: 0.8125rem;
  color: var(--nv-text-tertiary, rgba(255,255,255,0.4));
  max-width: 340px;
}
.empty-state__action {
  margin-top: 8px;
}
</style>
