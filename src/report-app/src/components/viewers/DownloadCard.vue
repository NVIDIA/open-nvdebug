<template>
  <div class="nv-card nv-card--elevated" style="text-align: center;">
    <div style="font-size: 3rem; margin-bottom: 12px;">&#x1F4E6;</div>
    <h3 class="nv-section-title" style="margin-bottom: 8px;">{{ fileName }}</h3>
    <div style="margin-bottom: 4px;">
      <span class="nv-badge nv-badge--neutral">
        {{ fileType.toUpperCase() }}
      </span>
      <span class="nv-log__count" style="margin-left: 8px;">{{ formatBytes(fileSize) }}</span>
    </div>
    <p v-if="message" class="nv-log__count" style="margin: 12px 0;">{{ message }}</p>
    <a
      v-if="downloadUrl"
      :href="downloadUrl"
      download
      class="nv-btn nv-btn--primary nv-btn--lg"
      style="margin-top: 8px;"
    >
      Download File
    </a>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  fileName: string
  fileSize: number
  fileType: string
  downloadUrl?: string
  message?: string
}>(), {
  message: 'This file is too large or not a text format. Please download to view.',
})

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MB'
  return (b / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
}
</script>
