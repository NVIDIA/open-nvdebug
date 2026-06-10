<template>
  <div style="position: relative;">
    <input
      ref="inputRef"
      v-model="searchQuery"
      type="text"
      :placeholder="placeholder"
      @focus="showResults = true"
      @blur="onBlur"
      @keydown.escape="showResults = false"
      @keydown.enter="navigateFirst"
      @keydown.down.prevent="selectedIndex = Math.min(selectedIndex + 1, searchResults.length - 1)"
      @keydown.up.prevent="selectedIndex = Math.max(selectedIndex - 1, 0)"
      class="nv-input"
    />
    <!-- Results dropdown -->
    <div
      v-if="showResults && searchResults.length > 0"
      class="nv-card nv-card--elevated"
      style="position: absolute; top: 100%; left: 0; right: 0; z-index: 1000; border-radius: 0 0 8px 8px; max-height: 400px; overflow-y: auto; padding: 0;"
    >
      <div
        v-for="(result, i) in searchResults"
        :key="i"
        @mousedown.prevent="navigate(result.path)"
        :class="['nv-command__item', i === selectedIndex && 'nv-command__item--active']"
        style="border-bottom: 1px solid var(--nv-border);"
      >
        <div style="font-size: 0.8125rem; color: var(--nv-text-primary);">
          <span style="opacity: 0.5; font-size: 0.6875rem; margin-right: 6px;">{{ result.type }}</span>
          {{ result.label }}
        </div>
        <div style="font-size: 0.6875rem; color: var(--nv-text-secondary);">{{ result.sublabel }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSearch } from '@/composables/useSearch'

withDefaults(defineProps<{
  placeholder?: string
}>(), {
  placeholder: 'Search...',
})

const router = useRouter()
const { query: searchQuery, results: searchResults } = useSearch()
const showResults = ref(false)
const selectedIndex = ref(0)
const inputRef = ref<HTMLInputElement>()

function navigate(path: string) {
  router.push(path)
  showResults.value = false
  searchQuery.value = ''
}

function navigateFirst() {
  if (searchResults.value.length > 0) {
    navigate(searchResults.value[selectedIndex.value]?.path ?? searchResults.value[0].path)
  }
}

function onBlur() {
  setTimeout(() => { showResults.value = false }, 200)
}

defineExpose({ focus: () => inputRef.value?.focus() })
</script>
