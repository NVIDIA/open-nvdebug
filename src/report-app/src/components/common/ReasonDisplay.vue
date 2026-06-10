<template>
  <div v-if="text" class="rd" :class="{ 'rd--compact': compact }">
    <!-- Compact mode: truncated with expand -->
    <template v-if="compact && !expanded && isLong">
      <span class="rd__truncated" @click="expanded = true">
        {{ truncated }}
        <button class="rd__expand-btn" @click.stop="expanded = true">Show more</button>
      </span>
    </template>

    <!-- Full display (or compact-expanded, or non-compact) -->
    <template v-else>
      <div class="rd__body" :class="{ 'rd__body--collapsed': !compact && !expanded && isLong }">
        <!-- Full JSON -->
        <template v-if="parsed.type === 'json'">
          <pre class="rd__json" v-html="highlightJson(parsed.json)"></pre>
        </template>

        <!-- Mixed: text segments + embedded JSON blocks -->
        <template v-else-if="parsed.type === 'mixed'">
          <template v-for="(seg, i) in parsed.segments" :key="i">
            <span v-if="seg.kind === 'text'" class="rd__text">{{ seg.value }}</span>
            <pre v-else class="rd__json rd__json--inline" v-html="highlightJson(seg.value)"></pre>
          </template>
        </template>

        <!-- Delimited list -->
        <template v-else-if="parsed.type === 'delimited'">
          <ul class="rd__list">
            <li v-for="(item, i) in parsed.items" :key="i" class="rd__list-item">{{ item }}</li>
          </ul>
        </template>

        <!-- Plain text fallback -->
        <template v-else>
          <span class="rd__text">{{ text }}</span>
        </template>
      </div>

      <!-- Collapse/expand toggle for non-compact long content -->
      <button v-if="!compact && isLong" class="rd__toggle" @click="expanded = !expanded">
        {{ expanded ? 'Show less' : 'Show more' }}
      </button>

      <!-- Compact mode: collapse back -->
      <button v-if="compact && expanded && isLong" class="rd__expand-btn" @click="expanded = false">Show less</button>

      <!-- Copy (non-compact only) -->
      <button v-if="!compact" class="rd__copy" @click="copyRaw" :title="copyLabel">
        <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">
          <rect x="5.5" y="5.5" width="8" height="8" rx="1.5"/>
          <path d="M10.5 5.5V3.5a1.5 1.5 0 00-1.5-1.5H3.5A1.5 1.5 0 002 3.5V9a1.5 1.5 0 001.5 1.5h2"/>
        </svg>
        <span>{{ copyLabel }}</span>
      </button>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { copyToClipboard } from '@/utils/clipboard'
import { showToast } from '@/composables/useToast'

const props = withDefaults(defineProps<{
  text: string
  compact?: boolean
}>(), {
  compact: false,
})

const expanded = ref(false)
const copied = ref(false)

const TRUNCATE_LEN = 200
const LONG_THRESHOLD = 300

const isLong = computed(() => props.text.length > LONG_THRESHOLD)
const truncated = computed(() =>
  props.text.length > TRUNCATE_LEN
    ? props.text.slice(0, TRUNCATE_LEN) + '\u2026'
    : props.text
)

const copyLabel = computed(() => copied.value ? 'Copied' : 'Copy')

interface JsonSegment { kind: 'json'; value: string }
interface TextSegment { kind: 'text'; value: string }
type Segment = JsonSegment | TextSegment

interface ParsedJson { type: 'json'; json: string }
interface ParsedMixed { type: 'mixed'; segments: Segment[] }
interface ParsedDelimited { type: 'delimited'; items: string[] }
interface ParsedPlain { type: 'plain' }
type ParseResult = ParsedJson | ParsedMixed | ParsedDelimited | ParsedPlain

function tryParseJson(s: string): any | null {
  const trimmed = s.trim()
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null
  try { return JSON.parse(trimmed) } catch { /* continue */ }
  try {
    const fixed = trimmed.replace(/'/g, '"')
    return JSON.parse(fixed)
  } catch { return null }
}

function extractJsonBlocks(s: string): Segment[] | null {
  const segments: Segment[] = []
  let remaining = s
  let found = false

  while (remaining.length > 0) {
    const openIdx = findJsonStart(remaining)
    if (openIdx === -1) {
      if (remaining.trim()) segments.push({ kind: 'text', value: remaining.trim() })
      break
    }

    const before = remaining.slice(0, openIdx).trim()
    if (before) segments.push({ kind: 'text', value: before })

    const closeIdx = findMatchingClose(remaining, openIdx)
    if (closeIdx === -1) {
      segments.push({ kind: 'text', value: remaining.slice(openIdx) })
      break
    }

    const block = remaining.slice(openIdx, closeIdx + 1)
    const obj = tryParseJson(block)
    if (obj !== null) {
      segments.push({ kind: 'json', value: JSON.stringify(obj, null, 2) })
      found = true
    } else {
      segments.push({ kind: 'text', value: block })
    }
    remaining = remaining.slice(closeIdx + 1)
  }

  return found ? segments : null
}

function findJsonStart(s: string): number {
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '{' || s[i] === '[') return i
  }
  return -1
}

function findMatchingClose(s: string, start: number): number {
  const open = s[start]
  const close = open === '{' ? '}' : ']'
  let depth = 0
  let inStr = false
  let openQuote = ''
  let esc = false

  for (let i = start; i < s.length; i++) {
    const ch = s[i]
    if (esc) { esc = false; continue }
    if (ch === '\\' && inStr) { esc = true; continue }
    if (ch === '"' || ch === "'") {
      if (!inStr) { inStr = true; openQuote = ch }
      else if (ch === openQuote) { inStr = false; openQuote = '' }
    }
    if (!inStr) {
      if (ch === open) depth++
      else if (ch === close) {
        depth--
        if (depth === 0) return i
      }
    }
  }
  return -1
}

const parsed = computed<ParseResult>(() => {
  const s = props.text
  if (!s) return { type: 'plain' }

  const fullJson = tryParseJson(s)
  if (fullJson !== null) {
    return { type: 'json', json: JSON.stringify(fullJson, null, 2) }
  }

  if (s.includes('{') || s.includes('[')) {
    const segments = extractJsonBlocks(s)
    if (segments) return { type: 'mixed', segments }
  }

  if (s.includes(' | ')) {
    const items = s.split(' | ').map(x => x.trim()).filter(Boolean)
    if (items.length >= 2) return { type: 'delimited', items }
  }

  if (s.includes('; ')) {
    const items = s.split('; ').map(x => x.trim()).filter(Boolean)
    if (items.length >= 2) return { type: 'delimited', items }
  }

  return { type: 'plain' }
})

function highlightJson(json: string): string {
  return json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"([^"\\]*(\\.[^"\\]*)*)"\s*:/g, '<span class="rd-hl-key">"$1"</span>:')
    .replace(/:\s*"([^"\\]*(\\.[^"\\]*)*)"/g, ': <span class="rd-hl-str">"$1"</span>')
    .replace(/:\s*(\d+\.?\d*)/g, ': <span class="rd-hl-num">$1</span>')
    .replace(/:\s*(true|false|null)/g, ': <span class="rd-hl-kw">$1</span>')
}

async function copyRaw() {
  try {
    await copyToClipboard(props.text)
    copied.value = true
    showToast('Copied to clipboard', 'success')
    setTimeout(() => { copied.value = false }, 2000)
  } catch {
    showToast('Failed to copy', 'error')
  }
}
</script>

<style scoped>
.rd {
  font-size: 0.8125rem;
  line-height: 1.6;
  color: var(--nv-text-primary);
  position: relative;
}

.rd--compact {
  font-size: 0.75rem;
  line-height: 1.5;
}

.rd__truncated {
  color: var(--nv-text-secondary);
  word-break: break-word;
  cursor: default;
}

.rd__body--collapsed {
  max-height: 4.8em;
  overflow: hidden;
  mask-image: linear-gradient(to bottom, black 60%, transparent 100%);
  -webkit-mask-image: linear-gradient(to bottom, black 60%, transparent 100%);
}

.rd__text {
  font-family: var(--nv-font-mono);
  white-space: pre-wrap;
  word-break: break-word;
  display: block;
  margin-bottom: 4px;
}

.rd__json {
  font-family: var(--nv-font-mono);
  font-size: 0.75rem;
  line-height: 1.5;
  background: var(--nv-bg-tertiary);
  border: 1px solid var(--nv-border);
  border-radius: var(--nv-radius-sm);
  padding: 10px 12px;
  margin: 6px 0;
  overflow-x: auto;
  white-space: pre;
  word-break: normal;
}

.rd__json--inline {
  margin: 4px 0;
}

.rd__list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.rd__list-item {
  font-family: var(--nv-font-mono);
  font-size: 0.75rem;
  line-height: 1.5;
  word-break: break-word;
  padding: 6px 10px;
  background: var(--nv-bg-tertiary);
  border-radius: var(--nv-radius-sm);
  border-left: 3px solid var(--nv-border-strong);
}

.rd__toggle,
.rd__expand-btn {
  display: inline-block;
  background: none;
  border: none;
  color: var(--nv-accent);
  font: inherit;
  font-size: 0.75rem;
  font-weight: 600;
  cursor: pointer;
  padding: 2px 0;
  margin-top: 4px;
}
.rd__toggle:hover,
.rd__expand-btn:hover {
  text-decoration: underline;
}

.rd__copy {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: none;
  border: 1px solid var(--nv-border);
  border-radius: var(--nv-radius-sm);
  color: var(--nv-text-tertiary);
  font: inherit;
  font-size: 0.6875rem;
  cursor: pointer;
  padding: 2px 8px;
  margin-top: 8px;
  transition: all 0.15s ease;
}
.rd__copy:hover {
  color: var(--nv-text-primary);
  border-color: var(--nv-accent);
  background: var(--nv-bg-tertiary);
}

/* JSON syntax highlighting */
:deep(.rd-hl-key) { color: var(--nv-accent); }
:deep(.rd-hl-str) { color: var(--nv-info); }
:deep(.rd-hl-num) { color: var(--nv-warning); }
:deep(.rd-hl-kw) { color: var(--nv-error); font-weight: 600; }
</style>
