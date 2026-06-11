<template>
  <div ref="rootRef" :class="['gantt', { 'gantt--fullscreen': isFullscreen }]">
    <!-- Toolbar -->
    <div class="gantt__toolbar">
      <div class="gantt__toolbar-group gantt__zoom-group">
        <button @click="zoomOut" class="nv-btn nv-btn--sm" title="Zoom Out (Ctrl + Scroll Down)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M6.5 1a5.5 5.5 0 0 1 4.383 8.823l3.896 3.9a.75.75 0 0 1-1.06 1.06l-3.9-3.896A5.5 5.5 0 1 1 6.5 1zm0 1.5a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM4 6.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5z"/></svg>
        </button>
        <span class="gantt__zoom-pct" :title="pxPerSecond.toFixed(1) + ' px/s'">{{ zoomPercent }}%</span>
        <button @click="zoomIn" class="nv-btn nv-btn--sm" title="Zoom In (Ctrl + Scroll Up)">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M6.5 1a5.5 5.5 0 0 1 4.383 8.823l3.896 3.9a.75.75 0 0 1-1.06 1.06l-3.9-3.896A5.5 5.5 0 1 1 6.5 1zm0 1.5a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM6.5 3a.5.5 0 0 1 .5.5V6h2.5a.5.5 0 0 1 0 1H7v2.5a.5.5 0 0 1-1 0V7H3.5a.5.5 0 0 1 0-1H6V3.5a.5.5 0 0 1 .5-.5z"/></svg>
        </button>
        <button @click="fitToWidth" class="nv-btn nv-btn--sm" title="Fit to Width">Fit</button>
      </div>

      <div class="gantt__toolbar-group">
        <select v-if="dutOptions.length > 1" v-model="dutFilter" class="nv-select nv-select--sm" title="Filter by DUT">
          <option value="">All DUTs</option>
          <option v-for="d in dutOptions" :key="d" :value="d">{{ d }}</option>
        </select>
        <select v-model="statusFilter" class="nv-select nv-select--sm" title="Filter by status">
          <option value="">All Statuses</option>
          <option v-for="s in statusOptions" :key="s" :value="s">{{ s }}</option>
        </select>
        <select v-if="serviceOptions.length > 1" v-model="serviceFilter" class="nv-select nv-select--sm" title="Filter by service">
          <option value="">All Services</option>
          <option v-for="s in serviceOptions" :key="s" :value="s">{{ s }}</option>
        </select>
        <label class="gantt__check">
          <input type="checkbox" v-model="colorByService" />
          Color by service
        </label>
        <label class="gantt__check">
          <input type="checkbox" v-model="showNames" />
          Names
        </label>
        <label class="gantt__check">
          <input type="checkbox" v-model="highlightAnomalies" />
          Anomalies
        </label>
        <label class="gantt__check">
          <input type="checkbox" v-model="showGaps" />
          Gaps
        </label>
      </div>

      <span style="flex: 1;" />

      <!-- Legend -->
      <div class="gantt__legend">
        <template v-if="colorByService">
          <span v-for="s in serviceLegendItems" :key="s.service" class="gantt__legend-item">
            <span class="gantt__legend-dot" :style="{ background: s.color }" />
            {{ s.service }} ({{ s.count }})
          </span>
        </template>
        <template v-else>
          <span v-for="s in legendItems" :key="s.status" class="gantt__legend-item">
            <span class="gantt__legend-dot" :style="{ background: `var(--nv-${s.css})` }" />
            {{ s.label }} ({{ s.count }})
          </span>
        </template>
      </div>

      <button @click="toggleFullscreen" class="nv-btn nv-btn--sm" :title="isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'">
        {{ isFullscreen ? '\u2715' : '\u26F6' }}
      </button>
    </div>

    <!-- Chart area -->
    <div ref="scrollContainer" class="gantt__scroll" @wheel="onWheel">
      <div class="gantt__canvas" :style="{ width: canvasWidth + 'px', minHeight: '100%' }">
        <!-- Sticky time ruler -->
        <div class="gantt__ruler" :style="{ width: canvasWidth + 'px' }">
          <div class="gantt__ruler-label" :style="{ width: LABEL_WIDTH + 'px' }"></div>
          <div class="gantt__ruler-ticks">
            <span
              v-for="t in tickMarks"
              :key="t"
              class="gantt__tick"
              :style="{ left: (t * pxPerSecond) + 'px' }"
            >{{ formatTick(t) }}</span>
          </div>
        </div>

        <!-- DUT lanes -->
        <div v-for="row in visibleDutRows" :key="row.dutId" class="gantt__lane">
          <div class="gantt__lane-label" :style="{ width: LABEL_WIDTH + 'px' }" :title="dutSummaryTooltip(row.dutId)">
            <div>{{ row.dutId }}</div>
            <div class="gantt__lane-meta">
              {{ row.bars.length }} collectors
              <template v-if="showGaps && (dutGaps.get(row.dutId)?.length ?? 0) > 0">
                &middot; {{ dutGaps.get(row.dutId)!.length }} gaps
              </template>
            </div>
          </div>
          <div class="gantt__lane-bars" :style="{ height: row.height + 'px' }">
            <!-- Grid lines -->
            <div
              v-for="t in tickMarks"
              :key="'g' + t"
              class="gantt__gridline"
              :style="{ left: (t * pxPerSecond) + 'px' }"
            />
            <!-- Gap markers -->
            <template v-if="showGaps">
              <div
                v-for="gap in dutGaps.get(row.dutId) ?? []"
                :key="'gap-' + gap.start"
                class="gantt__gap"
                :style="{
                  left: (gap.start * pxPerSecond) + 'px',
                  width: Math.max(gap.duration * pxPerSecond, 4) + 'px',
                }"
                :title="`Idle gap: ${gap.duration.toFixed(1)}s`"
              >
                <span v-if="gap.duration * pxPerSecond > 30" class="gantt__gap-label">{{ gap.duration.toFixed(0) }}s</span>
              </div>
            </template>
            <!-- Bars -->
            <div
              v-for="bar in row.bars"
              :key="bar.id + ':' + bar.lane"
              :class="['gantt__bar', colorByService ? `gantt__bar--svc-${serviceKey(bar.group)}` : `gantt__bar--${bar.status}`, { 'gantt__bar--anomaly': isAnomaly(bar) }]"
              :style="{
                left: (bar.startOffset * pxPerSecond) + 'px',
                width: Math.max(bar.duration * pxPerSecond, 3) + 'px',
                top: (bar.lane * ROW_HEIGHT + BAR_PADDING) + 'px',
                height: BAR_HEIGHT + 'px',
                ...(colorByService ? { background: serviceBarColor(bar.group) } : {}),
              }"
              :title="`${bar.id} — ${bar.name}\n${bar.duration.toFixed(1)}s | ${bar.status}`"
              tabindex="0"
              @click="navigateToCollector(bar)"
              @mouseenter="showTooltip($event, bar)"
              @mouseleave="hideTooltip"
              @keydown.enter="navigateToCollector(bar)"
            >
              <span v-if="bar.duration * pxPerSecond > 50" class="gantt__bar-label">{{ showNames ? bar.name : bar.id }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Summary footer -->
    <div class="gantt__footer">
      <span>{{ filteredBars.length }} collectors</span>
      <span class="gantt__footer-sep">|</span>
      <span>{{ visibleDutRows.length }} DUTs</span>
      <span class="gantt__footer-sep">|</span>
      <span>{{ maxDuration.toFixed(1) }}s total</span>
      <span class="gantt__footer-sep">|</span>
      <span class="gantt__hint">Scroll to zoom &middot; Shift + scroll to pan</span>
    </div>

    <!-- Tooltip -->
    <Teleport to="body">
      <div v-if="tooltip.visible" class="gantt__tooltip" :style="{ left: tooltip.x + 'px', top: tooltip.y + 'px' }">
        <div class="gantt__tooltip-header">{{ tooltip.id }} — {{ tooltip.name }}</div>
        <div class="gantt__tooltip-row">
          <span>Status:</span>
          <span :class="`gantt__tooltip-status--${tooltip.status}`">{{ tooltip.status }}</span>
        </div>
        <div class="gantt__tooltip-row">
          <span>Duration:</span>
          <span>{{ tooltip.duration }}s</span>
        </div>
        <div class="gantt__tooltip-row">
          <span>Group:</span>
          <span>{{ tooltip.group }}</span>
        </div>
        <div v-if="tooltip.stages" class="gantt__tooltip-stages">
          <div v-for="(val, key) in tooltip.stages" :key="key" class="gantt__tooltip-row">
            <span>{{ key }}:</span>
            <span>{{ val !== null ? val.toFixed(2) + 's' : '—' }}</span>
          </div>
        </div>
        <div class="gantt__tooltip-hint">Click to view collector details</div>
      </div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'

interface PerDutCollector {
  id: string
  name: string
  group?: string
  duration: number
  start_time: string | null
  end_time: string | null
  status: string
  stage_timing?: {
    validation: number | null
    discovery: number | null
    execution: number | null
    post_processing: number | null
  }
}

interface GanttBar {
  id: string
  name: string
  group: string
  dutId: string
  startOffset: number
  duration: number
  status: string
  lane: number
  stageTiming?: PerDutCollector['stage_timing']
}

interface DutRow {
  dutId: string
  height: number
  maxLane: number
  bars: GanttBar[]
}

const props = withDefaults(defineProps<{
  perDut: Array<{
    dut_id: string
    duration: number
    collectors: PerDutCollector[]
  }>
  maxHeight?: string
}>(), {
  maxHeight: 'calc(100vh - 260px)',
})

const router = useRouter()
const rootRef = ref<HTMLElement>()
const scrollContainer = ref<HTMLElement>()

const ROW_HEIGHT = 28
const LABEL_WIDTH = 160
const BAR_HEIGHT = 20
const BAR_PADDING = 4

const pxPerSecond = ref(4)
const isFullscreen = ref(false)
const highlightAnomalies = ref(false)
const colorByService = ref(false)
const showNames = ref(false)
const showGaps = ref(false)
const dutFilter = ref('')
const statusFilter = ref('')
const serviceFilter = ref('')

const tooltip = ref({
  visible: false, x: 0, y: 0,
  id: '', name: '', status: '', duration: '', group: '',
  stages: null as Record<string, number | null> | null,
})

const dutOptions = computed(() => props.perDut.map(d => d.dut_id))
const statusOptions = computed(() => {
  const set = new Set<string>()
  for (const dut of props.perDut) {
    for (const c of dut.collectors) {
      if (c.start_time) set.add(c.status)
    }
  }
  return [...set].sort()
})

const serviceOptions = computed(() => {
  const set = new Set<string>()
  for (const dut of props.perDut) {
    for (const c of dut.collectors) {
      if (c.group) set.add(c.group)
    }
  }
  return [...set].sort()
})

const SERVICE_BAR_COLORS: Record<string, string> = {
  redfish: '#8b5cf6',
  ssh: '#06b6d4',
  ipmi: '#3b82f6',
  bmc: '#06b6d4',
  host: '#10b981',
  health_check: '#f59e0b',
  preflight: '#64748b',
}

function serviceKey(group: string): string {
  return group.toLowerCase().replace(/[\s-]/g, '_')
}

function serviceBarColor(group: string): string {
  return SERVICE_BAR_COLORS[serviceKey(group)] ?? '#6366f1'
}

const globalStart = computed(() => {
  let min = Infinity
  for (const dut of props.perDut) {
    for (const c of dut.collectors) {
      if (c.start_time) {
        const t = new Date(c.start_time).getTime() / 1000
        if (t < min) min = t
      }
    }
  }
  return min === Infinity ? 0 : min
})

const maxDuration = computed(() => {
  let max = 0
  for (const dut of props.perDut) {
    for (const c of dut.collectors) {
      if (c.start_time) {
        const end = (new Date(c.start_time).getTime() / 1000) - globalStart.value + c.duration
        if (end > max) max = end
      }
    }
    if (dut.duration > max) max = dut.duration
  }
  return max || 60
})

const allBars = computed<GanttBar[]>(() => {
  const bars: GanttBar[] = []
  for (const dut of props.perDut) {
    const lanes: number[] = []
    const sorted = [...dut.collectors]
      .filter(c => c.start_time)
      .sort((a, b) => new Date(a.start_time!).getTime() - new Date(b.start_time!).getTime())

    for (const c of sorted) {
      const startOffset = (new Date(c.start_time!).getTime() / 1000) - globalStart.value
      const endOffset = startOffset + c.duration

      let lane = 0
      for (let i = 0; i < lanes.length; i++) {
        if (lanes[i] <= startOffset + 0.01) { lane = i; break }
        lane = i + 1
      }
      if (lane >= lanes.length) lanes.push(0)
      lanes[lane] = endOffset

      bars.push({
        id: c.id, name: c.name, group: c.group ?? '', dutId: dut.dut_id,
        startOffset, duration: c.duration, status: c.status, lane,
        stageTiming: c.stage_timing,
      })
    }
  }
  return bars
})

const filteredBars = computed(() => {
  let bars = allBars.value
  if (dutFilter.value) bars = bars.filter(b => b.dutId === dutFilter.value)
  if (statusFilter.value) bars = bars.filter(b => b.status === statusFilter.value)
  if (serviceFilter.value) bars = bars.filter(b => b.group === serviceFilter.value)
  return bars
})

const anomalyIds = computed(() => {
  const ids = new Set<string>()
  if (!highlightAnomalies.value) return ids
  const durations = allBars.value.map(b => b.duration).filter(d => d > 0)
  if (durations.length < 3) return ids
  durations.sort((a, b) => a - b)
  const median = durations[Math.floor(durations.length / 2)]
  const threshold = median * 2
  for (const bar of allBars.value) {
    if (bar.duration > threshold) ids.add(bar.id + ':' + bar.dutId)
  }
  return ids
})

function isAnomaly(bar: GanttBar): boolean {
  return highlightAnomalies.value && anomalyIds.value.has(bar.id + ':' + bar.dutId)
}

interface GapInfo {
  start: number
  duration: number
}

const dutGaps = computed(() => {
  const gapMap = new Map<string, GapInfo[]>()
  const gapThreshold = 2

  for (const dut of props.perDut) {
    const sorted = [...dut.collectors]
      .filter(c => c.start_time)
      .sort((a, b) => new Date(a.start_time!).getTime() - new Date(b.start_time!).getTime())

    const gaps: GapInfo[] = []
    for (let i = 0; i < sorted.length - 1; i++) {
      const endTime = (new Date(sorted[i].start_time!).getTime() / 1000) - globalStart.value + sorted[i].duration
      const nextStart = (new Date(sorted[i + 1].start_time!).getTime() / 1000) - globalStart.value
      const gapDuration = nextStart - endTime
      if (gapDuration > gapThreshold) {
        gaps.push({ start: endTime, duration: gapDuration })
      }
    }
    if (gaps.length > 0) gapMap.set(dut.dut_id, gaps)
  }
  return gapMap
})

function dutSummaryTooltip(dutId: string): string {
  const dut = props.perDut.find(d => d.dut_id === dutId)
  if (!dut) return dutId
  const bars = filteredBars.value.filter(b => b.dutId === dutId)
  const activeTime = bars.reduce((sum, b) => sum + b.duration, 0)
  const gaps = dutGaps.value.get(dutId) ?? []
  const idleTime = gaps.reduce((sum, g) => sum + g.duration, 0)
  return `${dutId}\n${bars.length} collectors | Active: ${activeTime.toFixed(1)}s | Idle: ${idleTime.toFixed(1)}s | Gaps: ${gaps.length}`
}

const visibleDutRows = computed<DutRow[]>(() => {
  const dutsToShow = dutFilter.value
    ? props.perDut.filter(d => d.dut_id === dutFilter.value)
    : props.perDut

  return dutsToShow.map(dut => {
    const bars = filteredBars.value.filter(b => b.dutId === dut.dut_id)
    const maxLane = bars.length > 0 ? Math.max(...bars.map(b => b.lane)) : 0
    return {
      dutId: dut.dut_id,
      height: (maxLane + 1) * ROW_HEIGHT + 8,
      maxLane,
      bars,
    }
  })
})

const canvasWidth = computed(() => LABEL_WIDTH + maxDuration.value * pxPerSecond.value + 60)

const tickMarks = computed(() => {
  const step = niceStep(maxDuration.value)
  const ticks: number[] = []
  for (let t = 0; t <= maxDuration.value + step; t += step) ticks.push(t)
  return ticks
})

function niceStep(total: number): number {
  const rough = total / 10
  const mag = Math.pow(10, Math.floor(Math.log10(rough)))
  const norm = rough / mag
  if (norm <= 1) return mag
  if (norm <= 2) return 2 * mag
  if (norm <= 5) return 5 * mag
  return 10 * mag
}

function formatTick(t: number): string {
  if (t < 60) return `${t}s`
  const m = Math.floor(t / 60)
  const s = Math.round(t % 60)
  return s === 0 ? `${m}m` : `${m}m${s}s`
}

const legendItems = computed(() => {
  const counts: Record<string, number> = {}
  for (const b of filteredBars.value) {
    counts[b.status] = (counts[b.status] || 0) + 1
  }
  const map: Record<string, { label: string; css: string }> = {
    success: { label: 'Success', css: 'success' },
    error: { label: 'Error', css: 'error' },
    partial: { label: 'Partial', css: 'warning' },
    skipped: { label: 'Skipped', css: 'text-tertiary' },
  }
  return Object.entries(counts)
    .map(([status, count]) => ({
      status,
      label: map[status]?.label ?? status,
      css: map[status]?.css ?? 'text-tertiary',
      count,
    }))
    .sort((a, b) => b.count - a.count)
})

const serviceLegendItems = computed(() => {
  const counts: Record<string, number> = {}
  for (const b of filteredBars.value) {
    counts[b.group] = (counts[b.group] || 0) + 1
  }
  return Object.entries(counts)
    .map(([service, count]) => ({
      service,
      color: serviceBarColor(service),
      count,
    }))
    .sort((a, b) => b.count - a.count)
})

const basePxPerSecond = ref(0)

const zoomPercent = computed(() => {
  if (basePxPerSecond.value <= 0) return 100
  return Math.round((pxPerSecond.value / basePxPerSecond.value) * 100)
})

function zoomIn() { pxPerSecond.value = Math.min(pxPerSecond.value * 1.5, 80) }
function zoomOut() { pxPerSecond.value = Math.max(pxPerSecond.value / 1.5, 0.5) }

function fitToWidth() {
  const el = scrollContainer.value
  if (!el || maxDuration.value <= 0) return
  pxPerSecond.value = Math.max(0.5, (el.clientWidth - LABEL_WIDTH - 60) / maxDuration.value)
  basePxPerSecond.value = pxPerSecond.value
}

function onWheel(e: WheelEvent) {
  if (e.shiftKey) return
  e.preventDefault()
  if (e.deltaY < 0) zoomIn()
  else zoomOut()
}

function toggleFullscreen() {
  const el = rootRef.value
  if (!el) return
  if (!isFullscreen.value) {
    el.requestFullscreen?.()
    isFullscreen.value = true
  } else {
    document.exitFullscreen?.()
    isFullscreen.value = false
  }
  nextTick(fitToWidth)
}

function showTooltip(event: MouseEvent, bar: GanttBar) {
  const x = Math.min(event.clientX + 14, window.innerWidth - 320)
  const y = Math.min(event.clientY - 10, window.innerHeight - 200)
  tooltip.value = {
    visible: true, x, y,
    id: bar.id, name: bar.name, status: bar.status,
    duration: bar.duration.toFixed(2),
    group: bar.group,
    stages: bar.stageTiming ? { ...bar.stageTiming } : null,
  }
}

function hideTooltip() {
  tooltip.value.visible = false
}

function navigateToCollector(bar: GanttBar) {
  router.push(`/dut/${encodeURIComponent(bar.dutId)}/${encodeURIComponent(bar.group)}/${encodeURIComponent(bar.id)}`)
}

let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  fitToWidth()
  resizeObserver = new ResizeObserver(() => {
    nextTick(fitToWidth)
  })
  if (scrollContainer.value) resizeObserver.observe(scrollContainer.value)
})

onUnmounted(() => {
  resizeObserver?.disconnect()
})

watch(() => props.perDut, () => nextTick(fitToWidth))
</script>

<style scoped>
.gantt {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-lg, 12px);
  overflow: hidden;
  background: var(--nv-glass-bg);
}
.gantt--fullscreen {
  position: fixed;
  inset: 0;
  z-index: 2000;
  border-radius: 0;
  background: var(--nv-app-bg);
}

.gantt__toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--nv-glass-border);
  flex-wrap: wrap;
  flex-shrink: 0;
}
.gantt__toolbar-group {
  display: flex;
  align-items: center;
  gap: 6px;
}
.gantt__meta {
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  min-width: 50px;
}
.gantt__check {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  cursor: pointer;
}
.gantt__check input { accent-color: var(--nv-accent); }

.gantt__legend {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}
.gantt__legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.6875rem;
  color: var(--nv-text-secondary);
}
.gantt__legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.gantt__scroll {
  flex: 1;
  overflow: auto;
  position: relative;
}
.gantt__canvas {
  position: relative;
  min-width: 100%;
}

/* Time ruler */
.gantt__ruler {
  display: flex;
  position: sticky;
  top: 0;
  z-index: 3;
  height: 28px;
  background: var(--nv-glass-bg-dense);
  border-bottom: 1px solid var(--nv-glass-border);
}
.gantt__ruler-label {
  flex-shrink: 0;
  position: sticky;
  left: 0;
  z-index: 4;
  background: var(--nv-glass-bg-dense);
}
.gantt__ruler-ticks {
  position: relative;
  flex: 1;
}
.gantt__tick {
  position: absolute;
  top: 8px;
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  transform: translateX(-50%);
  white-space: nowrap;
}

/* DUT lanes */
.gantt__lane {
  display: flex;
  border-bottom: 1px solid var(--nv-glass-border);
}
.gantt__lane:nth-child(even) .gantt__lane-bars {
  background: var(--nv-glass-bg-light);
}
.gantt__lane-label {
  flex-shrink: 0;
  position: sticky;
  left: 0;
  z-index: 2;
  padding: 6px 8px;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--nv-text-primary);
  background: var(--nv-glass-bg-dense);
  border-right: 1px solid var(--nv-glass-border);
  display: flex;
  flex-direction: column;
  justify-content: center;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.gantt__lane-bars {
  position: relative;
  flex: 1;
  min-height: 36px;
}

/* Grid lines */
.gantt__gridline {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--nv-glass-border);
  opacity: 0.4;
  pointer-events: none;
}

/* Bars */
.gantt__bar {
  position: absolute;
  border-radius: 3px;
  cursor: pointer;
  display: flex;
  align-items: center;
  overflow: hidden;
  transition: opacity 0.1s, box-shadow 0.1s;
  outline: none;
}
.gantt__bar:hover {
  opacity: 0.85;
  box-shadow: 0 0 0 2px var(--nv-accent);
  z-index: 1;
}
.gantt__bar:focus-visible {
  box-shadow: 0 0 0 2px var(--nv-accent);
  z-index: 1;
}
.gantt__bar--success { background: var(--nv-success); }
.gantt__bar--error { background: var(--nv-error); }
.gantt__bar--partial { background: var(--nv-warning); }
.gantt__bar--skipped { background: var(--nv-text-tertiary); }
.gantt__bar--complete { background: var(--nv-success); }
.gantt__bar--anomaly {
  box-shadow: 0 0 0 2px var(--nv-warning);
  animation: gantt-pulse 1.5s ease-in-out infinite;
}
@keyframes gantt-pulse {
  0%, 100% { box-shadow: 0 0 0 2px var(--nv-warning); }
  50% { box-shadow: 0 0 0 4px var(--nv-warning), 0 0 8px var(--nv-warning); }
}
.gantt__bar-label {
  padding: 0 4px;
  font-size: 0.625rem;
  color: var(--nv-text-strong);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  text-shadow: 0 1px 2px rgba(0,0,0,0.4);
}

/* Gap markers */
.gantt__gap {
  position: absolute;
  top: 0;
  bottom: 0;
  background: repeating-linear-gradient(
    -45deg,
    transparent,
    transparent 3px,
    var(--nv-warning-muted) 3px,
    var(--nv-warning-muted) 6px
  );
  opacity: 0.5;
  border-left: 1px dashed var(--nv-warning);
  border-right: 1px dashed var(--nv-warning);
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: auto;
  z-index: 0;
}
.gantt__gap:hover {
  opacity: 0.8;
}
.gantt__gap-label {
  font-size: 0.5625rem;
  font-family: var(--nv-font-mono);
  color: var(--nv-warning);
  font-weight: 700;
  white-space: nowrap;
  text-shadow: 0 1px 2px var(--nv-surface-primary);
}

.gantt__lane-meta {
  font-size: 0.5625rem;
  font-weight: 400;
  color: var(--nv-text-tertiary);
  white-space: nowrap;
}

/* Footer */
.gantt__footer {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  padding: 6px 12px;
  font-size: 0.6875rem;
  color: var(--nv-text-tertiary);
  border-top: 1px solid var(--nv-glass-border);
  flex-shrink: 0;
}
.gantt__footer-sep { opacity: 0.4; margin: 0 4px; }
.gantt__hint {
  font-style: italic;
  opacity: 0.7;
}

.gantt__zoom-group {
  background: var(--nv-glass-bg-light);
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md, 8px);
  padding: 2px 4px;
  gap: 2px;
}
.gantt__zoom-group .nv-btn--sm {
  min-width: 30px;
  height: 28px;
  padding: 0 6px;
  font-size: 0.875rem;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.gantt__zoom-pct {
  min-width: 42px;
  text-align: center;
  font-size: 0.6875rem;
  font-weight: 600;
  font-family: var(--nv-font-mono, monospace);
  color: var(--nv-text-secondary);
}

/* Tooltip */
.gantt__tooltip {
  position: fixed;
  z-index: 3000;
  background: var(--nv-glass-bg-dense, rgba(20,20,20,0.97));
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--nv-glass-border);
  border-radius: 8px;
  padding: 10px 14px;
  min-width: 200px;
  max-width: 320px;
  pointer-events: none;
  box-shadow: var(--nv-glass-shadow);
}
.gantt__tooltip-header {
  font-weight: 600;
  font-size: 0.8125rem;
  color: var(--nv-text-primary);
  margin-bottom: 6px;
}
.gantt__tooltip-row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  font-size: 0.75rem;
  color: var(--nv-text-secondary);
  line-height: 1.6;
}
.gantt__tooltip-row span:first-child {
  color: var(--nv-text-tertiary);
  text-transform: capitalize;
}
.gantt__tooltip-status--success { color: var(--nv-success); font-weight: 600; }
.gantt__tooltip-status--error { color: var(--nv-error); font-weight: 600; }
.gantt__tooltip-status--partial { color: var(--nv-warning); font-weight: 600; }
.gantt__tooltip-status--skipped { color: var(--nv-text-tertiary); }
.gantt__tooltip-stages {
  margin-top: 6px;
  padding-top: 6px;
  border-top: 1px solid var(--nv-glass-border);
}
.gantt__tooltip-hint {
  margin-top: 6px;
  font-size: 0.625rem;
  color: var(--nv-text-tertiary);
  font-style: italic;
}
</style>
