<template>
  <div ref="rootRef" class="log-tl">
    <!-- Toolbar -->
    <div class="log-tl__toolbar">
      <div class="log-tl__toolbar-group">
        <button @click="zoomOut" class="nv-btn nv-btn--sm" title="Zoom Out">&minus;</button>
        <button @click="fitToWidth" class="nv-btn nv-btn--sm" title="Fit to Width">Fit</button>
        <button @click="zoomIn" class="nv-btn nv-btn--sm" title="Zoom In">+</button>
        <span class="log-tl__meta">{{ filteredEvents.length }}<template v-if="filteredEvents.length !== events.length"> / {{ events.length }}</template> events</span>
      </div>
      <span style="flex: 1;" />
      <div class="log-tl__level-pills">
        <button
          v-for="lv in LEVEL_DEFS"
          :key="lv.key"
          :class="['log-tl__pill', { 'log-tl__pill--off': hiddenLevels.has(lv.key) }]"
          :style="{ '--pill-color': lv.color }"
          @click="toggleLevel(lv.key)"
          :title="hiddenLevels.has(lv.key) ? `Show ${lv.label} events` : `Hide ${lv.label} events`"
        >
          <span class="log-tl__pill-dot" :style="{ background: hiddenLevels.has(lv.key) ? 'var(--nv-text-tertiary)' : lv.color }" />
          {{ lv.label }}
          <span class="log-tl__pill-count">{{ levelCounts[lv.key] ?? 0 }}</span>
        </button>
      </div>
      <button v-if="brushRange" class="nv-btn nv-btn--ghost nv-btn--sm" @click="clearBrush">
        Clear selection
      </button>
    </div>

    <!-- SVG area -->
    <div ref="scrollContainer" class="log-tl__scroll" @wheel="onWheel">
      <svg
        :width="svgWidth"
        :height="svgHeight"
        @mousedown="onBrushStart"
        @mousemove="onMouseMove"
        @mouseup="onBrushEnd"
        @mouseleave="onMouseLeave"
      >
        <!-- Density heatmap strip -->
        <g :transform="`translate(${LABEL_WIDTH}, 0)`">
          <rect
            v-for="(bin, i) in densityBins"
            :key="'d' + i"
            :x="bin.x"
            :y="0"
            :width="bin.width"
            :height="DENSITY_HEIGHT"
            :fill="bin.color"
            :opacity="0.7"
          />
        </g>

        <!-- Time axis -->
        <g :transform="`translate(${LABEL_WIDTH}, ${DENSITY_HEIGHT})`">
          <line x1="0" :y1="0" :x2="timelineWidth" :y2="0" stroke="var(--nv-glass-border)" />
          <g v-for="t in tickMarks" :key="'t' + t">
            <line :x1="timeToX(t)" :y1="0" :x2="timeToX(t)" :y2="8" stroke="var(--nv-text-tertiary)" stroke-width="1" />
            <text :x="timeToX(t)" :y="20" text-anchor="middle" fill="var(--nv-text-tertiary)" font-size="10">{{ formatTime(t) }}</text>
          </g>
        </g>

        <!-- Lanes -->
        <g :transform="`translate(0, ${DENSITY_HEIGHT + AXIS_HEIGHT})`">
          <!-- Lane backgrounds + labels -->
          <g v-for="(src, i) in sources" :key="'lane' + i">
            <rect
              v-if="i % 2 === 0"
              :x="0"
              :y="i * LANE_HEIGHT"
              :width="svgWidth"
              :height="LANE_HEIGHT"
              fill="var(--nv-glass-bg-light)"
              opacity="0.3"
            />
            <line
              :x1="LABEL_WIDTH" :y1="(i + 1) * LANE_HEIGHT"
              :x2="svgWidth" :y2="(i + 1) * LANE_HEIGHT"
              stroke="var(--nv-glass-border)" opacity="0.3"
            />
            <text
              :x="8"
              :y="i * LANE_HEIGHT + LANE_HEIGHT / 2 + 4"
              :fill="LANE_COLORS[i % LANE_COLORS.length]"
              font-size="11"
              font-weight="600"
            >{{ truncLabel(src) }}</text>
          </g>

          <!-- Grid lines -->
          <line
            v-for="t in tickMarks" :key="'gl' + t"
            :x1="LABEL_WIDTH + timeToX(t)"
            :y1="0"
            :x2="LABEL_WIDTH + timeToX(t)"
            :y2="sources.length * LANE_HEIGHT"
            stroke="var(--nv-glass-border)" opacity="0.15"
          />

          <!-- Event dots -->
          <circle
            v-for="(evt, i) in visibleEvents"
            :key="'e' + i"
            :cx="LABEL_WIDTH + timeToX(evt.timestamp)"
            :cy="evt.sourceIndex * LANE_HEIGHT + LANE_HEIGHT / 2"
            :r="dotRadius(evt)"
            :fill="levelFill(evt.level)"
            :opacity="isBrushed(evt) ? 1 : (brushRange ? 0.15 : 0.85)"
            class="log-tl__dot"
            @mouseenter="showTooltip($event, evt, i)"
            @mouseleave="hideTooltip"
            @click.stop="$emit('selectEvent', i)"
          />

          <!-- Brush selection overlay -->
          <rect
            v-if="brushing || brushRange"
            :x="LABEL_WIDTH + brushRect.x"
            :y="0"
            :width="brushRect.width"
            :height="sources.length * LANE_HEIGHT"
            fill="var(--nv-accent)"
            opacity="0.12"
            stroke="var(--nv-accent)"
            stroke-width="1"
            stroke-dasharray="4 2"
            pointer-events="none"
          />
        </g>
      </svg>
    </div>

    <!-- Tooltip -->
    <Teleport to="body">
      <div v-if="tooltipData.visible" class="log-tl__tooltip" :style="{ left: tooltipData.x + 'px', top: tooltipData.y + 'px' }">
        <div style="font-weight: 600; margin-bottom: 2px;">{{ tooltipData.source }}</div>
        <div :style="{ color: levelCssVar(tooltipData.level), fontWeight: 600, fontSize: '0.6875rem' }">{{ tooltipData.level }}</div>
        <div style="color: var(--nv-text-secondary); font-size: 0.6875rem;">{{ tooltipData.time }}</div>
        <div style="margin-top: 4px; max-width: 300px; word-break: break-word; font-size: 0.6875rem; color: var(--nv-text-primary);">{{ tooltipData.message }}</div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted, onUnmounted, nextTick, watch } from 'vue'

export interface TimelineEvent {
  timestamp: number
  source: string
  sourceIndex: number
  level?: string
  message: string
}

const LEVEL_DEFS = [
  { key: 'error', label: 'Error', color: 'var(--nv-error)' },
  { key: 'warning', label: 'Warning', color: 'var(--nv-warning)' },
  { key: 'info', label: 'Info', color: 'var(--nv-info)' },
  { key: 'debug', label: 'Debug', color: 'var(--nv-text-tertiary)' },
] as const

type LevelKey = typeof LEVEL_DEFS[number]['key']

const props = defineProps<{
  events: TimelineEvent[]
  sources: string[]
}>()

const emit = defineEmits<{
  brushRange: [range: { start: number; end: number } | null]
  selectEvent: [index: number]
  levelFilter: [hiddenLevels: Set<string>]
}>()

const hiddenLevels = reactive(new Set<string>())

function normalizeLevel(level?: string): LevelKey {
  switch (level?.toLowerCase()) {
    case 'error': case 'critical': case 'fatal': return 'error'
    case 'warning': case 'warn': return 'warning'
    case 'info': case 'notice': return 'info'
    default: return 'debug'
  }
}

const levelCounts = computed(() => {
  const counts: Record<string, number> = { error: 0, warning: 0, info: 0, debug: 0 }
  for (const e of props.events) {
    counts[normalizeLevel(e.level)]++
  }
  return counts
})

function toggleLevel(key: string) {
  if (hiddenLevels.has(key)) hiddenLevels.delete(key)
  else hiddenLevels.add(key)
  emit('levelFilter', new Set(hiddenLevels))
}

const filteredEvents = computed(() => {
  if (hiddenLevels.size === 0) return props.events
  return props.events.filter(e => !hiddenLevels.has(normalizeLevel(e.level)))
})

const rootRef = ref<HTMLElement>()
const scrollContainer = ref<HTMLElement>()

const LABEL_WIDTH = 180
const LANE_HEIGHT = 32
const DENSITY_HEIGHT = 20
const AXIS_HEIGHT = 28
const DOT_R = 4

const pxPerMs = ref(0.05)

const LANE_COLORS = [
  '#3b82f6', '#8b5cf6', '#06b6d4', '#f59e0b', '#10b981',
  '#ef4444', '#ec4899', '#6366f1', '#14b8a6', '#f97316',
]

const tooltipData = ref({
  visible: false, x: 0, y: 0,
  source: '', level: '', time: '', message: '',
})

const timeRange = computed(() => {
  if (props.events.length === 0) return { min: 0, max: 1000 }
  let min = Infinity, max = -Infinity
  for (const e of props.events) {
    if (e.timestamp < min) min = e.timestamp
    if (e.timestamp > max) max = e.timestamp
  }
  const pad = (max - min) * 0.02 || 500
  return { min: min - pad, max: max + pad }
})

const timeSpan = computed(() => timeRange.value.max - timeRange.value.min)
const timelineWidth = computed(() => Math.max(timeSpan.value * pxPerMs.value, 200))
const svgWidth = computed(() => LABEL_WIDTH + timelineWidth.value + 40)
const svgHeight = computed(() => DENSITY_HEIGHT + AXIS_HEIGHT + props.sources.length * LANE_HEIGHT + 10)

function timeToX(ts: number): number {
  return (ts - timeRange.value.min) * pxPerMs.value
}

const visibleEvents = computed(() => {
  const src = filteredEvents.value
  if (src.length <= 5000) return src
  const step = Math.ceil(src.length / 5000)
  return src.filter((_, i) => i % step === 0)
})

const densityBins = computed(() => {
  const BIN_COUNT = Math.min(Math.max(Math.round(timelineWidth.value / 4), 50), 300)
  const binWidth = timelineWidth.value / BIN_COUNT
  const binMs = timeSpan.value / BIN_COUNT
  const counts = new Array(BIN_COUNT).fill(0)
  let maxCount = 0

  for (const e of filteredEvents.value) {
    const idx = Math.min(Math.floor((e.timestamp - timeRange.value.min) / binMs), BIN_COUNT - 1)
    if (idx >= 0) {
      counts[idx]++
      if (counts[idx] > maxCount) maxCount = counts[idx]
    }
  }

  if (maxCount === 0) return []

  return counts.map((count, i) => {
    const ratio = count / maxCount
    const r = Math.round(40 + 180 * ratio)
    const g = Math.round(180 - 130 * ratio)
    const b = Math.round(60 - 30 * ratio)
    return {
      x: i * binWidth,
      width: binWidth + 0.5,
      color: count === 0 ? 'transparent' : `rgb(${r}, ${g}, ${b})`,
    }
  })
})

// Tick marks
const tickMarks = computed(() => {
  const step = niceStep(timeSpan.value)
  const first = Math.ceil(timeRange.value.min / step) * step
  const ticks: number[] = []
  for (let t = first; t <= timeRange.value.max; t += step) ticks.push(t)
  return ticks
})

function niceStep(total: number): number {
  const rough = total / 8
  const mag = Math.pow(10, Math.floor(Math.log10(rough)))
  const norm = rough / mag
  if (norm <= 1) return mag
  if (norm <= 2) return 2 * mag
  if (norm <= 5) return 5 * mag
  return 10 * mag
}

function formatTime(ms: number): string {
  if (ms < 1e10) {
    return ms < 60000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
  }
  const d = new Date(ms)
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`
}

function truncLabel(s: string): string {
  const name = s.split('/').pop() ?? s
  return name.length > 28 ? name.slice(0, 27) + '\u2026' : name
}

function dotRadius(evt: TimelineEvent): number {
  const lev = evt.level?.toLowerCase()
  return lev === 'error' || lev === 'critical' ? DOT_R + 1 : DOT_R
}

function levelFill(level?: string): string {
  switch (level?.toLowerCase()) {
    case 'error': case 'critical': case 'fatal': return 'var(--nv-error)'
    case 'warning': case 'warn': return 'var(--nv-warning)'
    case 'info': case 'notice': return 'var(--nv-info)'
    default: return 'var(--nv-text-tertiary)'
  }
}

function levelCssVar(level: string): string {
  return levelFill(level)
}

// Zoom
function zoomIn() { pxPerMs.value = Math.min(pxPerMs.value * 1.5, 2) }
function zoomOut() { pxPerMs.value = Math.max(pxPerMs.value / 1.5, 0.001) }
function fitToWidth() {
  const el = scrollContainer.value
  if (el && timeSpan.value > 0) {
    pxPerMs.value = Math.max(0.001, (el.clientWidth - LABEL_WIDTH - 40) / timeSpan.value)
  }
}
function onWheel(e: WheelEvent) {
  if (!e.ctrlKey && !e.metaKey) return
  e.preventDefault()
  if (e.deltaY < 0) zoomIn()
  else zoomOut()
}

// Brush selection
const brushing = ref(false)
const brushStartX = ref(0)
const brushEndX = ref(0)
const brushRange = ref<{ start: number; end: number } | null>(null)

const brushRect = computed(() => {
  if (brushRange.value) {
    const x = timeToX(brushRange.value.start)
    const w = timeToX(brushRange.value.end) - x
    return { x, width: Math.max(w, 1) }
  }
  if (!brushing.value) return { x: 0, width: 0 }
  const x = Math.min(brushStartX.value, brushEndX.value)
  const w = Math.abs(brushEndX.value - brushStartX.value)
  return { x, width: Math.max(w, 1) }
})

function isBrushed(evt: TimelineEvent): boolean {
  if (!brushRange.value) return true
  return evt.timestamp >= brushRange.value.start && evt.timestamp <= brushRange.value.end
}

function onBrushStart(e: MouseEvent) {
  if (e.button !== 0) return
  const svg = (e.currentTarget as SVGSVGElement)
  const rect = svg.getBoundingClientRect()
  const mx = e.clientX - rect.left - LABEL_WIDTH
  if (mx < 0) return
  brushing.value = true
  brushStartX.value = mx / pxPerMs.value + timeRange.value.min
  brushEndX.value = brushStartX.value
  brushRange.value = null
  emit('brushRange', null)
}

function onMouseMove(e: MouseEvent) {
  if (!brushing.value) return
  const svg = (e.currentTarget as SVGSVGElement)
  const rect = svg.getBoundingClientRect()
  const mx = e.clientX - rect.left - LABEL_WIDTH
  brushEndX.value = mx / pxPerMs.value + timeRange.value.min
}

function onBrushEnd() {
  if (!brushing.value) return
  brushing.value = false
  const start = Math.min(brushStartX.value, brushEndX.value)
  const end = Math.max(brushStartX.value, brushEndX.value)
  if (end - start > timeSpan.value * 0.005) {
    brushRange.value = { start, end }
    emit('brushRange', brushRange.value)
  }
}

function onMouseLeave() {
  if (brushing.value) onBrushEnd()
  hideTooltip()
}

function clearBrush() {
  brushRange.value = null
  emit('brushRange', null)
}

function showTooltip(e: MouseEvent, evt: TimelineEvent, _idx: number) {
  tooltipData.value = {
    visible: true,
    x: Math.min(e.clientX + 14, window.innerWidth - 340),
    y: Math.min(e.clientY - 10, window.innerHeight - 160),
    source: evt.source.split('/').pop() ?? evt.source,
    level: evt.level ?? 'UNKNOWN',
    time: formatTime(evt.timestamp),
    message: evt.message.length > 200 ? evt.message.slice(0, 200) + '\u2026' : evt.message,
  }
}

function hideTooltip() {
  tooltipData.value.visible = false
}

let resizeObs: ResizeObserver | null = null
onMounted(() => {
  fitToWidth()
  resizeObs = new ResizeObserver(() => nextTick(fitToWidth))
  if (scrollContainer.value) resizeObs.observe(scrollContainer.value)
})
onUnmounted(() => resizeObs?.disconnect())
watch(() => props.events, () => nextTick(fitToWidth))
</script>

<style scoped>
.log-tl {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-lg, 12px);
  overflow: hidden;
  background: var(--nv-glass-bg);
}
.log-tl__toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--nv-glass-border);
  flex-shrink: 0;
}
.log-tl__toolbar-group {
  display: flex;
  align-items: center;
  gap: 6px;
}
.log-tl__meta {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
}
.log-tl__level-pills {
  display: flex;
  gap: 4px;
}
.log-tl__pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.6875rem;
  border: 1px solid var(--pill-color);
  background: color-mix(in srgb, var(--pill-color) 12%, transparent);
  color: var(--pill-color);
  cursor: pointer;
  font-weight: 600;
  transition: all 0.15s ease;
}
.log-tl__pill:hover { background: color-mix(in srgb, var(--pill-color) 22%, transparent); }
.log-tl__pill--off {
  border-color: var(--nv-glass-border);
  background: transparent;
  color: var(--nv-text-tertiary);
  font-weight: 400;
  opacity: 0.6;
}
.log-tl__pill--off:hover { opacity: 0.9; }
.log-tl__pill-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}
.log-tl__pill-count {
  font-family: var(--nv-font-mono, monospace);
  font-size: 0.5625rem;
  opacity: 0.7;
}
.log-tl__scroll {
  flex: 1;
  overflow: auto;
  max-height: 400px;
  cursor: crosshair;
}
.log-tl__dot {
  cursor: pointer;
  transition: opacity 0.15s;
}
.log-tl__dot:hover {
  stroke: var(--nv-text-primary);
  stroke-width: 2;
}

.log-tl__tooltip {
  position: fixed;
  z-index: 3000;
  background: var(--nv-glass-bg-dense, rgba(20,20,20,0.97));
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--nv-glass-border);
  border-radius: 8px;
  padding: 10px 14px;
  max-width: 320px;
  pointer-events: none;
  box-shadow: var(--nv-glass-shadow);
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
}
</style>
