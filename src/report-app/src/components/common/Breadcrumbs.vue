<template>
  <nav class="breadcrumbs" aria-label="Breadcrumb">
    <template v-for="(item, i) in items" :key="i">
      <span v-if="i > 0" class="breadcrumb-sep">/</span>
      <router-link v-if="item.to" :to="item.to" class="breadcrumb-link">
        {{ item.label }}
      </router-link>
      <span v-else class="breadcrumb-current">{{ item.label }}</span>
    </template>
  </nav>
</template>

<script setup lang="ts">
export interface BreadcrumbItem {
  label: string
  to?: string
}

defineProps<{
  items: BreadcrumbItem[]
}>()
</script>

<style scoped>
.breadcrumbs {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.8125rem;
}

.breadcrumb-sep {
  color: var(--nv-text-secondary);
}

.breadcrumb-link {
  color: var(--nv-accent);
  text-decoration: none;
}

.breadcrumb-link:hover {
  text-decoration: underline;
}

.breadcrumb-current {
  color: var(--nv-text-primary);
}
</style>
