<template>
  <div class="vexec">
    <div v-if="timelineEntries.length > 0" class="vexec__intro nv-glass--accent">
      <div>
        <div class="vexec__eyebrow">Collector Run Timeline</div>
        <p>
          Shows the selected DUT's collectors in execution order, with idle gaps,
          runtime hotspots, failures, and per-collector stage timing.
        </p>
      </div>
      <div class="vexec__metric-grid">
        <div class="vexec__metric">
          <span>Collection Span</span>
          <strong>{{ formatDuration(wallClockDuration) }}</strong>
        </div>
        <div class="vexec__metric">
          <span>Active Collector Time</span>
          <strong>{{ formatDuration(activeCollectorTime) }}</strong>
        </div>
        <div class="vexec__metric">
          <span>Idle / Overhead</span>
          <strong>{{ formatDuration(idleOrOverheadTime) }}</strong>
        </div>
        <div class="vexec__metric">
          <span>Longest Collector</span>
          <strong>{{ longestCollectorLabel }}</strong>
        </div>
      </div>
    </div>

    <div class="vexec__toolbar">
      <div class="vexec__filters">
        <select v-if="dutOptions.length > 1" v-model="dutFilter" class="nv-select nv-select--sm" title="Filter by DUT">
          <option value="">All DUTs (compare)</option>
          <option v-for="d in dutOptions" :key="d" :value="d">{{ d }}</option>
        </select>
        <select v-if="serviceOptions.length > 1" v-model="serviceFilter" class="nv-select nv-select--sm" title="Filter by service">
          <option value="">All Services</option>
          <option v-for="s in serviceOptions" :key="s" :value="s">{{ s }}</option>
        </select>
        <select v-model="statusFilter" class="nv-select nv-select--sm" title="Filter by status">
          <option value="">All Statuses</option>
          <option v-for="s in statusOptions" :key="s" :value="s">{{ s }}</option>
        </select>
      </div>
      <div class="vexec__summary">
        <span>{{ selectedScopeLabel }}</span>
        <span>{{ filteredEntries.length }} collectors</span>
        <span>{{ filteredDutCount }} DUTs</span>
        <span>{{ issueCount }} issues</span>
      </div>
    </div>

    <div v-if="timelineEntries.length > 0" class="vexec__overview nv-glass--subtle">
      <div class="vexec__overview-header">
        <span>Run Position Map</span>
        <span>{{ formatDuration(collectorSpan) }} collector span</span>
      </div>
      <div class="vexec__dots">
        <button
          v-for="entry in filteredEntries"
          :key="entry.key"
          :class="['vexec__dot', `vexec__dot--${normalizeStatus(entry.status)}`]"
          :style="{
            left: dotLeft(entry) + '%',
            width: dotSize(entry.duration) + 'px',
            height: dotSize(entry.duration) + 'px',
          }"
          :title="`Jump to ${entry.id} ${entry.dutId} - ${formatDuration(entry.duration)}`"
          type="button"
          @click="scrollToCollector(entry)"
        />
      </div>
      <div class="vexec__scale">
        <span>{{ formatClock(scopedStartMs) }}</span>
        <span>{{ formatClock(scopedEndMs) }}</span>
      </div>
    </div>

    <div v-if="timelineEntries.length === 0" class="vexec__empty">
      No timestamped collector executions found for the current filters.
    </div>

    <div v-else class="vexec__list" :style="{ maxHeight }">
      <template v-for="item in timelineEntries" :key="item.key">
        <div v-if="item.kind === 'gap'" class="vexec__gap">
          <span class="vexec__gap-line" />
          <span class="vexec__gap-label">Idle Gap: {{ formatDuration(item.duration) }}</span>
        </div>

        <article
          v-else
          :id="eventElementId(item)"
          :class="['vexec__event', `vexec__event--${normalizeStatus(item.status)}`]"
          tabindex="0"
          @click="navigateToCollector(item)"
          @keydown.enter="navigateToCollector(item)"
        >
          <div class="vexec__time">
            <span>{{ formatClock(item.startMs) }}</span>
            <span>{{ formatDuration(item.startOffset) }}</span>
          </div>
          <div class="vexec__spine">
            <span class="vexec__marker" />
          </div>
          <div class="vexec__card">
            <div class="vexec__card-head">
              <div>
                <div class="vexec__title">{{ item.id }} - {{ item.name }}</div>
                <div class="vexec__meta">{{ item.dutId }} / {{ item.group || 'unknown' }}</div>
              </div>
              <div class="vexec__badges">
                <span v-if="isSlowest(item)" class="vexec__badge--accent">Slowest</span>
                <span v-if="isRuntimeHotspot(item)" class="vexec__badge--warning">Runtime Hotspot</span>
                <span :class="['vexec__status', `vexec__status--${normalizeStatus(item.status)}`]">{{ item.status }}</span>
                <span>{{ formatDuration(item.duration) }}</span>
                <span>{{ runtimeShare(item).toFixed(1) }}% of span</span>
                <span v-if="item.truncated" class="vexec__truncated">timestamp inferred</span>
              </div>
            </div>

            <div class="vexec__duration" :title="durationTitle(item)">
              <span
                class="vexec__duration-fill"
                :style="{ width: durationPercent(item) + '%' }"
              />
            </div>

            <div class="vexec__waterfall" :title="waterfallTitle(item)">
              <div
                v-for="segment in stageSegments(item)"
                :key="segment.name"
                :class="['vexec__segment', `vexec__segment--${segment.name}`]"
                :style="{ width: segment.width + '%' }"
              >
                <span v-if="segment.width >= 12">{{ stageLabel(segment.name) }}</span>
              </div>
              <div v-if="stageSegments(item).length === 0" class="vexec__segment vexec__segment--unknown">
                No stage timing
              </div>
            </div>

            <div class="vexec__stage-row">
              <span v-for="stage in visibleStages(item)" :key="stage.name">
                {{ stageLabel(stage.name) }} {{ formatDuration(stage.value) }}
              </span>
            </div>
          </div>
        </article>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { formatDuration } from '@/utils/format'

interface StageTiming {
  validation: number | null
  discovery: number | null
  execution: number | null
  post_processing: number | null
}

interface PerDutCollector {
  id: string
  name: string
  group?: string
  duration: number
  start_time: string | null
  end_time: string | null
  status: string
  stage_timing?: StageTiming
}

interface TimelineEvent {
  kind: 'event'
  key: string
  id: string
  name: string
  group: string
  dutId: string
  duration: number
  startMs: number
  endMs: number
  startOffset: number
  status: string
  stageTiming?: StageTiming
  truncated: boolean
}

interface GapEvent {
  kind: 'gap'
  key: string
  startMs: number
  duration: number
}

type TimelineItem = TimelineEvent | GapEvent
type StageName = keyof StageTiming

const props = withDefaults(defineProps<{
  perDut: Array<{
    dut_id: string
    duration: number
    collectors: PerDutCollector[]
  }>
  totalDuration?: number
  maxHeight?: string
}>(), {
  totalDuration: 0,
  maxHeight: 'calc(100vh - 260px)',
})

const router = useRouter()
const dutFilter = ref(props.perDut[0]?.dut_id ?? '')
const serviceFilter = ref('')
const statusFilter = ref('')

const GAP_THRESHOLD_SECONDS = 2
const STAGE_ORDER: StageName[] = ['validation', 'discovery', 'execution', 'post_processing']
const HOTSPOT_SHARE_THRESHOLD = 25
const HOTSPOT_DURATION_THRESHOLD = 30

watch(
  () => props.perDut.map(d => d.dut_id).join('|'),
  () => {
    if (dutFilter.value && props.perDut.some(d => d.dut_id === dutFilter.value)) return
    dutFilter.value = props.perDut[0]?.dut_id ?? ''
  },
  { immediate: true },
)

const allEntries = computed<TimelineEvent[]>(() => {
  const entries: TimelineEvent[] = []
  for (const dut of props.perDut) {
    for (const collector of dut.collectors) {
      const startMs = parseTimestamp(collector.start_time)
      if (startMs == null) continue
      const parsedEndMs = parseTimestamp(collector.end_time)
      const duration = Math.max(Number(collector.duration) || 0, 0)
      const endMs = parsedEndMs ?? startMs + duration * 1000
      entries.push({
        kind: 'event',
        key: `${dut.dut_id}:${collector.id}:${startMs}`,
        id: collector.id,
        name: collector.name,
        group: collector.group ?? '',
        dutId: dut.dut_id,
        duration,
        startMs,
        endMs,
        startOffset: 0,
        status: collector.status,
        stageTiming: collector.stage_timing,
        truncated: parsedEndMs == null || duration === 0,
      })
    }
  }
  return entries.sort((a, b) => a.startMs - b.startMs)
})

const scopedBaseEntries = computed(() => {
  return allEntries.value
    .filter(entry => !dutFilter.value || entry.dutId === dutFilter.value)
    .filter(entry => !serviceFilter.value || entry.group === serviceFilter.value)
    .filter(entry => !statusFilter.value || entry.status === statusFilter.value)
})

const selectedDut = computed(() => props.perDut.find(d => d.dut_id === dutFilter.value))
const selectedScopeLabel = computed(() => dutFilter.value || 'All DUTs')
const configuredWallClockDuration = computed(() => {
  if (selectedDut.value?.duration && selectedDut.value.duration > 0) return selectedDut.value.duration
  return props.totalDuration > 0 ? props.totalDuration : 0
})

const scopedStartMs = computed(() => scopedBaseEntries.value[0]?.startMs ?? allEntries.value[0]?.startMs ?? Date.now())
const lastCollectorEndMs = computed(() => {
  return scopedBaseEntries.value.reduce((max, entry) => Math.max(max, entry.endMs), scopedStartMs.value)
})
const scopedEndMs = computed(() => {
  const configuredEnd = configuredWallClockDuration.value > 0
    ? scopedStartMs.value + configuredWallClockDuration.value * 1000
    : lastCollectorEndMs.value
  return Math.max(lastCollectorEndMs.value, configuredEnd)
})

const filteredEntries = computed<TimelineEvent[]>(() => {
  return scopedBaseEntries.value
    .map(entry => ({
      ...entry,
      startOffset: Math.max(0, (entry.startMs - scopedStartMs.value) / 1000),
    }))
})

const timelineEntries = computed<TimelineItem[]>(() => {
  const items: TimelineItem[] = []
  let previousEndMs: number | null = null
  for (const entry of filteredEntries.value) {
    if (previousEndMs != null) {
      const gap = Math.max(0, (entry.startMs - previousEndMs) / 1000)
      if (gap > GAP_THRESHOLD_SECONDS) {
        items.push({
          kind: 'gap',
          key: `gap:${previousEndMs}:${entry.startMs}`,
          startMs: previousEndMs,
          duration: gap,
        })
      }
    }
    items.push(entry)
    previousEndMs = Math.max(previousEndMs ?? entry.endMs, entry.endMs)
  }
  return items
})

const dutOptions = computed(() => props.perDut.map(d => d.dut_id).sort())
const serviceOptions = computed(() => unique(allEntries.value.map(e => e.group).filter(Boolean)))
const statusOptions = computed(() => unique(allEntries.value.map(e => e.status).filter(Boolean)))

const filteredDutCount = computed(() => new Set(filteredEntries.value.map(e => e.dutId)).size)
const activeCollectorTime = computed(() => filteredEntries.value.reduce((sum, entry) => sum + entry.duration, 0))
const collectorSpan = computed(() => Math.max(0, (lastCollectorEndMs.value - scopedStartMs.value) / 1000))
const wallClockDuration = computed(() => configuredWallClockDuration.value || collectorSpan.value)
const timelineSpan = computed(() => Math.max(wallClockDuration.value, collectorSpan.value))
const idleGapTime = computed(() => {
  return timelineEntries.value.reduce((sum, item) => item.kind === 'gap' ? sum + item.duration : sum, 0)
})
const idleOrOverheadTime = computed(() => Math.max(idleGapTime.value, wallClockDuration.value - activeCollectorTime.value))
const issueCount = computed(() => filteredEntries.value.filter(entry => {
  const status = normalizeStatus(entry.status)
  return status === 'error' || status === 'partial'
}).length)
const slowestEntry = computed(() => {
  return filteredEntries.value.reduce<TimelineEvent | null>((slowest, entry) => {
    if (!slowest || entry.duration > slowest.duration) return entry
    return slowest
  }, null)
})
const longestCollectorLabel = computed(() => {
  const entry = slowestEntry.value
  if (!entry) return 'None'
  return `${entry.id} (${formatDuration(entry.duration)})`
})

function parseTimestamp(value: string | null): number | null {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? null : parsed
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b))
}

function formatClock(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function normalizeStatus(status: string): string {
  const s = (status || '').toLowerCase()
  if (s === 'passed' || s === 'complete' || s === 'completed') return 'success'
  if (s === 'failed') return 'error'
  return s || 'unknown'
}

function dotLeft(entry: TimelineEvent): number {
  if (timelineSpan.value <= 0) return 0
  return Math.max(0, Math.min(100, ((entry.startMs - scopedStartMs.value) / 1000 / timelineSpan.value) * 100))
}

function dotSize(duration: number): number {
  if (duration <= 0) return 6
  return Math.max(6, Math.min(18, 6 + Math.log10(duration + 1) * 5))
}

function stageLabel(stage: string): string {
  return stage.replace('_', ' ')
}

function visibleStages(entry: TimelineEvent): Array<{ name: StageName; value: number }> {
  if (!entry.stageTiming) return []
  return STAGE_ORDER
    .map(name => ({ name, value: Number(entry.stageTiming?.[name] ?? 0) }))
    .filter(stage => stage.value > 0)
}

function stageSegments(entry: TimelineEvent): Array<{ name: StageName; width: number }> {
  const stages = visibleStages(entry)
  const total = stages.reduce((sum, stage) => sum + stage.value, 0)
  if (total <= 0) return []
  return stages.map(stage => ({
    name: stage.name,
    width: Math.max(2, (stage.value / total) * 100),
  }))
}

function waterfallTitle(entry: TimelineEvent): string {
  const stages = visibleStages(entry)
  if (stages.length === 0) return 'No stage timing available'
  return stages.map(stage => `${stageLabel(stage.name)}: ${formatDuration(stage.value)}`).join('\n')
}

function runtimeShare(entry: TimelineEvent): number {
  if (wallClockDuration.value <= 0) return 0
  return Math.max(0, (entry.duration / wallClockDuration.value) * 100)
}

function durationPercent(entry: TimelineEvent): number {
  if (wallClockDuration.value <= 0) return 0
  return Math.max(2, Math.min(100, runtimeShare(entry)))
}

function durationTitle(entry: TimelineEvent): string {
  return `${entry.id}: ${formatDuration(entry.duration)} (${runtimeShare(entry).toFixed(1)}% of selected DUT span)`
}

function isSlowest(entry: TimelineEvent): boolean {
  return slowestEntry.value?.key === entry.key
}

function isRuntimeHotspot(entry: TimelineEvent): boolean {
  return runtimeShare(entry) >= HOTSPOT_SHARE_THRESHOLD && entry.duration >= HOTSPOT_DURATION_THRESHOLD
}

function eventElementId(entry: TimelineEvent): string {
  return `timeline-event-${entry.dutId}-${entry.id}-${entry.startMs}`
}

function scrollToCollector(entry: TimelineEvent): void {
  const element = document.getElementById(eventElementId(entry))
  element?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  if (typeof element?.focus === 'function') {
    element.focus({ preventScroll: true })
  }
}

function navigateToCollector(entry: TimelineEvent): void {
  router.push(`/dut/${entry.dutId}/${entry.group}/${entry.id}`)
}
</script>

<style scoped>
.vexec {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.vexec__intro {
  display: grid;
  grid-template-columns: minmax(240px, 1fr) minmax(320px, 1.4fr);
  gap: 16px;
  align-items: stretch;
  padding: 14px 16px;
  border-radius: var(--nv-radius-lg);
}

.vexec__eyebrow {
  margin-bottom: 4px;
  color: var(--nv-text-primary);
  font-size: 0.875rem;
  font-weight: 700;
}

.vexec__intro p {
  max-width: 720px;
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
  line-height: 1.45;
}

.vexec__metric-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.vexec__metric {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 8px 10px;
  border: 1px solid var(--nv-glass-border);
  border-radius: var(--nv-radius-md);
  background: var(--nv-bg-secondary);
}

.vexec__metric span {
  color: var(--nv-text-tertiary);
  font-size: 0.625rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.vexec__metric strong {
  overflow: hidden;
  color: var(--nv-text-primary);
  font-size: 0.8125rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.vexec__toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.vexec__filters,
.vexec__summary {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.vexec__summary {
  color: var(--nv-text-secondary);
  font-size: 0.75rem;
}

.vexec__summary span {
  padding: 3px 8px;
  border-radius: var(--nv-radius-sm);
  background: var(--nv-bg-secondary);
}

.vexec__overview {
  padding: 10px 12px;
  border-radius: var(--nv-radius-md);
}

.vexec__overview-header,
.vexec__scale {
  display: flex;
  justify-content: space-between;
  color: var(--nv-text-secondary);
  font-size: 0.6875rem;
}

.vexec__overview-header {
  margin-bottom: 8px;
  font-weight: 600;
}

.vexec__dots {
  position: relative;
  height: 38px;
  margin: 0 10px;
  border-radius: var(--nv-radius-sm);
  background:
    linear-gradient(90deg, var(--nv-border-subtle) 1px, transparent 1px),
    var(--nv-bg-tertiary);
  background-size: 10% 100%;
  overflow: visible;
}

.vexec__dot {
  position: absolute;
  top: 50%;
  padding: 0;
  border: 0;
  border-radius: 999px;
  transform: translate(-50%, -50%);
  background: var(--nv-info);
  box-shadow: 0 0 0 2px color-mix(in srgb, currentColor 20%, transparent);
  cursor: pointer;
}

.vexec__dot:hover,
.vexec__dot:focus-visible {
  z-index: 2;
  outline: 2px solid var(--nv-text-primary);
  outline-offset: 2px;
}

.vexec__dot--success { background: var(--nv-success); }
.vexec__dot--partial { background: var(--nv-warning); }
.vexec__dot--skipped { background: var(--nv-skipped); }
.vexec__dot--error { background: var(--nv-error); }

.vexec__scale {
  margin-top: 4px;
}

.vexec__empty {
  padding: 24px;
  text-align: center;
  color: var(--nv-text-secondary);
  border: 1px dashed var(--nv-border-subtle);
  border-radius: var(--nv-radius-md);
}

.vexec__list {
  overflow: auto;
  padding-right: 8px;
}

.vexec__event {
  display: grid;
  grid-template-columns: 88px 22px minmax(0, 1fr);
  gap: 8px;
  cursor: pointer;
}

.vexec__event:focus-visible {
  outline: 2px solid var(--nv-accent);
  outline-offset: 2px;
}

.vexec__time {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 3px;
  padding-top: 12px;
  color: var(--nv-text-secondary);
  font-family: var(--nv-font-mono);
  font-size: 0.6875rem;
}

.vexec__time span:last-child {
  color: var(--nv-text-tertiary);
}

.vexec__spine {
  position: relative;
}

.vexec__spine::before {
  content: "";
  position: absolute;
  top: 0;
  bottom: -8px;
  left: 10px;
  width: 2px;
  background: var(--nv-border-subtle);
}

.vexec__marker {
  position: absolute;
  top: 14px;
  left: 4px;
  width: 14px;
  height: 14px;
  border-radius: 999px;
  background: var(--nv-info);
  border: 2px solid var(--nv-bg-primary);
  z-index: 1;
}

.vexec__event--success .vexec__marker { background: var(--nv-success); }
.vexec__event--partial .vexec__marker { background: var(--nv-warning); }
.vexec__event--skipped .vexec__marker { background: var(--nv-skipped); }
.vexec__event--error .vexec__marker { background: var(--nv-error); }

.vexec__card {
  margin-bottom: 8px;
  padding: 10px 12px;
  border: 1px solid var(--nv-border-subtle);
  border-radius: var(--nv-radius-md);
  background: var(--nv-bg-secondary);
}

.vexec__event:hover .vexec__card {
  border-color: var(--nv-accent);
}

.vexec__card-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.vexec__title {
  color: var(--nv-text-primary);
  font-size: 0.8125rem;
  font-weight: 600;
}

.vexec__meta,
.vexec__stage-row {
  color: var(--nv-text-secondary);
  font-size: 0.6875rem;
}

.vexec__badges {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
  color: var(--nv-text-secondary);
  font-size: 0.6875rem;
}

.vexec__badges span {
  padding: 2px 6px;
  border-radius: var(--nv-radius-sm);
  background: var(--nv-bg-tertiary);
}

.vexec__badge--accent {
  color: #000000;
  background: var(--nv-accent) !important;
  font-weight: 700;
}

.vexec__badge--warning {
  color: #000000;
  background: var(--nv-warning) !important;
  font-weight: 700;
}

.vexec__status--success { color: var(--nv-success); }
.vexec__status--partial { color: var(--nv-warning); }
.vexec__status--skipped { color: var(--nv-skipped); }
.vexec__status--error { color: var(--nv-error); }

.vexec__truncated {
  color: var(--nv-warning) !important;
}

.vexec__duration {
  position: relative;
  height: 8px;
  margin-bottom: 8px;
  overflow: hidden;
  border-radius: var(--nv-radius-full);
  background: var(--nv-bg-tertiary);
}

.vexec__duration-fill {
  position: absolute;
  inset: 0 auto 0 0;
  min-width: 2px;
  border-radius: inherit;
  background: linear-gradient(90deg, var(--nv-accent-bold), var(--nv-accent));
}

.vexec__waterfall {
  display: flex;
  height: 18px;
  overflow: hidden;
  border-radius: var(--nv-radius-sm);
  background: var(--nv-bg-tertiary);
}

.vexec__segment {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 2px;
  color: var(--nv-bg-primary);
  font-size: 0.5625rem;
  font-weight: 700;
  text-transform: uppercase;
  white-space: nowrap;
}

.vexec__segment--validation { background: #60a5fa; }
.vexec__segment--discovery { background: #a78bfa; }
.vexec__segment--execution { background: #76b900; }
.vexec__segment--post_processing { background: #f59e0b; }
.vexec__segment--unknown {
  width: 100%;
  color: var(--nv-text-tertiary);
  background: var(--nv-bg-tertiary);
}

.vexec__stage-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 6px;
}

.vexec__gap {
  display: grid;
  grid-template-columns: 88px 22px minmax(0, 1fr);
  gap: 8px;
  align-items: center;
  min-height: 28px;
  color: var(--nv-text-tertiary);
  font-size: 0.6875rem;
}

.vexec__gap-line {
  grid-column: 2;
  justify-self: center;
  width: 2px;
  height: 100%;
  min-height: 28px;
  background: repeating-linear-gradient(
    to bottom,
    var(--nv-border-subtle) 0,
    var(--nv-border-subtle) 4px,
    transparent 4px,
    transparent 8px
  );
}

.vexec__gap-label {
  grid-column: 3;
  padding: 4px 8px;
  border: 1px dashed var(--nv-border-subtle);
  border-radius: var(--nv-radius-sm);
  background: var(--nv-bg-tertiary);
}

@media (max-width: 1100px) {
  .vexec__intro {
    grid-template-columns: 1fr;
  }

  .vexec__metric-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
