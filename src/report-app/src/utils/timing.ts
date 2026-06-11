export interface DurationBucket {
  label: string
  min: number
  max: number
  count: number
  percent: number
}

export interface SlowCollector {
  id: string
  name: string
  group: string
  dutId: string
  duration: number
}

const BUCKETS: Array<Omit<DurationBucket, 'count' | 'percent'>> = [
  { label: '< 1s', min: 0, max: 1 },
  { label: '1-10s', min: 1, max: 10 },
  { label: '10-60s', min: 10, max: 60 },
  { label: '1-5m', min: 60, max: 300 },
  { label: '> 5m', min: 300, max: Number.POSITIVE_INFINITY },
]

export function buildDurationBuckets(durations: number[]): DurationBucket[] {
  const positiveDurations = durations.filter(duration => duration > 0)
  if (positiveDurations.length === 0) return []

  const counts = new Array(BUCKETS.length).fill(0) as number[]
  for (const duration of positiveDurations) {
    const index = BUCKETS.findIndex(bucket => duration >= bucket.min && duration < bucket.max)
    counts[index >= 0 ? index : counts.length - 1]++
  }

  return BUCKETS.map((bucket, index) => ({
    ...bucket,
    count: counts[index],
    percent: Math.round((counts[index] / positiveDurations.length) * 100),
  }))
}

export function topSlowCollectors(collectors: SlowCollector[], limit = 5): SlowCollector[] {
  return [...collectors]
    .filter(collector => collector.duration > 0)
    .sort((a, b) => b.duration - a.duration)
    .slice(0, limit)
}

export function hasTimingValues(timing: Record<string, number | null | undefined>): boolean {
  return Object.values(timing).some(value => typeof value === 'number' && value > 0)
}

export function normalizeCollectorId(id: string): string {
  return id.trim().toLowerCase()
}
