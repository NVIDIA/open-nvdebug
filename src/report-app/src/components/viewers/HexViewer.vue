<template>
  <div class="nv-log">
    <div class="nv-log__toolbar">
      <span class="nv-log__count">Hex Preview (first {{ Math.min(content.length, maxBytes) }} bytes)</span>
    </div>
    <pre class="nv-log__content" style="margin: 0; padding: 12px; overflow-x: auto; font-size: 0.6875rem;">{{ hexDump }}</pre>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  content: string
  maxBytes?: number
}>(), {
  maxBytes: 4096,
})

const hexDump = computed(() => {
  const bytes = props.content.slice(0, props.maxBytes)
  const lines: string[] = []
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16)
    const hex = Array.from(chunk).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
    const ascii = Array.from(chunk).map(c => {
      const code = c.charCodeAt(0)
      return code >= 32 && code < 127 ? c : '.'
    }).join('')
    lines.push(`${offset.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  |${ascii}|`)
  }
  return lines.join('\n')
})
</script>
