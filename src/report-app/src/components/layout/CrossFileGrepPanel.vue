<template>
  <div v-if="searchStore.grepPanelOpen" class="nv-sidebar" style="width: 350px; border-left: 1px solid var(--nv-border); border-right: none;">
    <!-- Header -->
    <div style="padding: 8px 12px; border-bottom: 1px solid var(--nv-border); display: flex; align-items: center; gap: 8px;">
      <span style="font-weight: 600; font-size: 0.8125rem; color: var(--nv-text-primary);">Search in Files</span>
      <span style="flex: 1;" />
      <button @click="searchStore.togglePanel()" class="nv-btn nv-btn--ghost nv-btn--sm">&times;</button>
    </div>

    <!-- Search input -->
    <div style="padding: 8px 12px; display: flex; gap: 6px; flex-wrap: wrap;">
      <input v-model="query" type="text" placeholder="Search pattern..." @keydown.enter="doGrep"
        class="nv-input" style="flex: 1;" />
      <label style="font-size: 0.6875rem; display: flex; align-items: center; gap: 4px; color: var(--nv-text-secondary);">
        <input type="checkbox" v-model="useRegex" /> Regex
      </label>
      <button @click="doGrep" class="nv-btn nv-btn--primary nv-btn--sm">Search</button>
    </div>

    <!-- Progress -->
    <div v-if="searchStore.grepSearching" style="padding: 4px 12px; font-size: 0.6875rem; color: var(--nv-text-secondary);">
      Searching {{ searchStore.grepFilesSearched }} / {{ searchStore.grepFilesTotal }} files...
    </div>

    <!-- Results -->
    <div style="flex: 1; overflow-y: auto; font-size: 0.75rem;">
      <EmptyState
        v-if="searchStore.grepResults.length === 0 && !searchStore.grepSearching"
        :icon="searchStore.grepQuery ? 'search' : 'file'"
        :title="searchStore.grepQuery ? 'No results found' : 'Enter a search pattern'"
      />
      <div
        v-for="(result, i) in searchStore.grepResults"
        :key="i"
        @click="navigateToResult(result)"
        class="nv-command__item"
        style="flex-direction: column; align-items: flex-start; border-bottom: 1px solid var(--nv-border);"
      >
        <div style="color: var(--nv-accent); font-size: 0.6875rem;">
          {{ result.filePath.split('/').pop() }}:{{ result.lineNumber }}
        </div>
        <div style="color: var(--nv-text-primary); font-family: monospace; font-size: 0.6875rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; width: 100%;">
          {{ result.lineContent }}
        </div>
      </div>
      <div v-if="searchStore.grepResults.length > 0" style="padding: 8px 12px; font-size: 0.6875rem; color: var(--nv-text-secondary); text-align: center;">
        {{ searchStore.grepResults.length }} results found
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSearchStore, type GrepResult } from '@/stores/search'
import { useCrossFileGrep } from '@/composables/useCrossFileGrep'
import EmptyState from '@/components/common/EmptyState.vue'

const searchStore = useSearchStore()
const { grep } = useCrossFileGrep()
const router = useRouter()
const query = ref('')
const useRegex = ref(false)

function doGrep() {
  if (query.value) grep(query.value, { regex: useRegex.value })
}

function navigateToResult(result: GrepResult) {
  router.push(`/file/${encodeURIComponent(result.filePath)}`)
}
</script>
