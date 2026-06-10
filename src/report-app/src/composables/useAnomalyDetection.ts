import {
  median as ssMedian,
  medianAbsoluteDeviation as ssMad,
  interquartileRange as ssIqr,
  quantile as ssQuantile,
  zScore as ssZScore,
  standardDeviation as ssStdDev,
  mean as ssMean,
} from 'simple-statistics'
import type { Manifest } from '@/types/manifest'

export type AnomalyType =
  | 'slow_collector'
  | 'cross_dut_slow'
  | 'high_failure_rate'
  | 'missing_files'
  | 'abnormal_log_size'
  | 'cross_dut_inconsistency'
  | 'execution_gap'

export interface Anomaly {
  id: string
  type: AnomalyType
  severity: 'critical' | 'warning' | 'info'
  title: string
  description: string
  dutId: string
  collectorId?: string
  value: number
  threshold: number
}

const SLOW_ABSOLUTE_MIN = 5
const MODIFIED_Z_THRESHOLD = 3.5
const LOCAL_Z_THRESHOLD = 3.0
const HIGH_FAIL_RATE = 0.3
const CRITICAL_FAIL_RATE = 0.5
const LOG_SIZE_Z_THRESHOLD = 3.0

export function detectAnomalies(manifest: Manifest): Anomaly[] {
  const anomalies: Anomaly[] = []
  let nextId = 0

  function pushAnomaly(a: Omit<Anomaly, 'id'>) {
    anomalies.push({ ...a, id: `anomaly-${nextId++}` })
  }

  // ──────────────────────────────────────────────────
  // 1. Per-collector-ID slow detection across DUTs
  //    Compare the SAME collector across different DUTs.
  //    E.g., R10 took 1.2s on 35 DUTs but 28s on one.
  // ──────────────────────────────────────────────────
  const collectorDurations = new Map<string, Array<{ dutId: string; duration: number; name: string }>>()

  for (const dut of manifest.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.execution_time <= 0) continue
        if (!collectorDurations.has(c.id)) collectorDurations.set(c.id, [])
        collectorDurations.get(c.id)!.push({
          dutId: dut.id,
          duration: c.execution_time,
          name: c.name,
        })
      }
    }
  }

  for (const [collectorId, entries] of collectorDurations) {
    if (entries.length < 2) continue
    const durations = entries.map(e => e.duration)
    const med = ssMedian(durations)
    const madVal = ssMad(durations)

    if (madVal > 0) {
      for (const entry of entries) {
        const modZ = 0.6745 * (entry.duration - med) / madVal
        if (modZ > MODIFIED_Z_THRESHOLD && entry.duration > SLOW_ABSOLUTE_MIN) {
          const p95 = ssQuantile(durations, 0.95)
          pushAnomaly({
            type: 'cross_dut_slow',
            severity: entry.duration > p95 * 2 ? 'critical' : 'warning',
            title: `Slow: ${collectorId} on ${entry.dutId}`,
            description: `${entry.name} took ${entry.duration.toFixed(1)}s on ${entry.dutId} vs median ${med.toFixed(1)}s across ${entries.length} DUTs (${(entry.duration / med).toFixed(1)}x, z=${modZ.toFixed(1)}).`,
            dutId: entry.dutId,
            collectorId,
            value: entry.duration,
            threshold: med * 3,
          })
        }
      }
    } else if (durations.length >= 2) {
      // MAD=0: most values are identical or nearly so. Use IQR, then multiplicative fallback.
      const iqr = ssIqr(durations)
      if (iqr > 0) {
        const q3 = ssQuantile(durations, 0.75)
        const upperFence = q3 + 1.5 * iqr
        for (const entry of entries) {
          if (entry.duration > upperFence && entry.duration > SLOW_ABSOLUTE_MIN) {
            pushAnomaly({
              type: 'cross_dut_slow',
              severity: 'warning',
              title: `Slow: ${collectorId} on ${entry.dutId}`,
              description: `${entry.name} took ${entry.duration.toFixed(1)}s on ${entry.dutId}, above IQR upper fence ${upperFence.toFixed(1)}s (median ${med.toFixed(1)}s across ${entries.length} DUTs).`,
              dutId: entry.dutId,
              collectorId,
              value: entry.duration,
              threshold: upperFence,
            })
          }
        }
      } else if (med > 0) {
        // Both MAD and IQR are 0 — population is constant. Flag any value >3x the median.
        for (const entry of entries) {
          const ratio = entry.duration / med
          if (ratio > 3 && entry.duration > SLOW_ABSOLUTE_MIN) {
            pushAnomaly({
              type: 'cross_dut_slow',
              severity: ratio > 10 ? 'critical' : 'warning',
              title: `Slow: ${collectorId} on ${entry.dutId}`,
              description: `${entry.name} took ${entry.duration.toFixed(1)}s on ${entry.dutId} vs ${med.toFixed(1)}s on all other DUTs (${ratio.toFixed(1)}x).`,
              dutId: entry.dutId,
              collectorId,
              value: entry.duration,
              threshold: med * 3,
            })
          }
        }
      }
    }
  }

  // ──────────────────────────────────────────────────
  // 2. Per-DUT local slow detection
  //    Within a single DUT, flag collectors that are
  //    abnormally slow relative to that DUT's population.
  // ──────────────────────────────────────────────────
  const crossDutFlagged = new Set(
    anomalies.filter(a => a.type === 'cross_dut_slow').map(a => `${a.dutId}:${a.collectorId}`)
  )

  for (const dut of manifest.duts) {
    const localDurations: number[] = []
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.execution_time > 0) localDurations.push(c.execution_time)
      }
    }
    if (localDurations.length < 4) continue

    const localMed = ssMedian(localDurations)
    const localMad = ssMad(localDurations)
    if (localMad <= 0) continue

    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.execution_time <= 0 || c.execution_time <= SLOW_ABSOLUTE_MIN) continue
        if (crossDutFlagged.has(`${dut.id}:${c.id}`)) continue

        const localZ = 0.6745 * (c.execution_time - localMed) / localMad
        if (localZ > LOCAL_Z_THRESHOLD) {
          pushAnomaly({
            type: 'slow_collector',
            severity: 'info',
            title: `Locally Slow: ${c.id}`,
            description: `${c.name} on ${dut.id} took ${c.execution_time.toFixed(1)}s — slow relative to this DUT's median of ${localMed.toFixed(1)}s (${(c.execution_time / localMed).toFixed(1)}x, z=${localZ.toFixed(1)}).`,
            dutId: dut.id,
            collectorId: c.id,
            value: c.execution_time,
            threshold: localMed * 3,
          })
        }
      }
    }
  }

  // ──────────────────────────────────────────────────
  // 3. Missing files — collector succeeded but no output
  // ──────────────────────────────────────────────────
  for (const dut of manifest.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if ((c.status === 'success' || c.status === 'partial') && c.files.length === 0) {
          pushAnomaly({
            type: 'missing_files',
            severity: 'warning',
            title: `No Files: ${c.id}`,
            description: `${c.name} on ${dut.id} completed with status "${c.status}" but produced no output files.`,
            dutId: dut.id,
            collectorId: c.id,
            value: 0,
            threshold: 1,
          })
        }
      }
    }
  }

  // ──────────────────────────────────────────────────
  // 4. High failure rate per DUT
  // ──────────────────────────────────────────────────
  for (const dut of manifest.duts) {
    const total = dut.status_summary.success + dut.status_summary.error +
      dut.status_summary.partial + dut.status_summary.skipped
    if (total <= 0) continue
    const failRate = dut.status_summary.error / total
    if (failRate > HIGH_FAIL_RATE) {
      pushAnomaly({
        type: 'high_failure_rate',
        severity: failRate > CRITICAL_FAIL_RATE ? 'critical' : 'warning',
        title: `High Failure Rate: ${dut.id}`,
        description: `${(failRate * 100).toFixed(0)}% of collectors failed on ${dut.id} (${dut.status_summary.error} errors out of ${total} executed).`,
        dutId: dut.id,
        value: failRate * 100,
        threshold: HIGH_FAIL_RATE * 100,
      })
    }
  }

  // ──────────────────────────────────────────────────
  // 5. Abnormal log size (MAD across DUTs)
  // ──────────────────────────────────────────────────
  const logSizes = manifest.duts.map(d => d.log_size)
  if (logSizes.length > 2) {
    const logMed = ssMedian(logSizes)
    const logMadVal = ssMad(logSizes)
    if (logMadVal > 0) {
      for (const dut of manifest.duts) {
        const modZ = 0.6745 * (dut.log_size - logMed) / logMadVal
        if (Math.abs(modZ) > LOG_SIZE_Z_THRESHOLD) {
          pushAnomaly({
            type: 'abnormal_log_size',
            severity: 'info',
            title: `Unusual Log Size: ${dut.id}`,
            description: `Log size ${formatBytes(dut.log_size)} is ${dut.log_size > logMed ? 'significantly larger' : 'significantly smaller'} than median (${formatBytes(logMed)}, z=${modZ.toFixed(1)}).`,
            dutId: dut.id,
            value: dut.log_size,
            threshold: logMed,
          })
        }
      }
    } else if (logMed > 0) {
      // MAD=0: most log sizes identical. Flag any that deviate >5x from median.
      for (const dut of manifest.duts) {
        const ratio = dut.log_size / logMed
        if (ratio > 5 || (ratio < 0.2 && ratio > 0)) {
          pushAnomaly({
            type: 'abnormal_log_size',
            severity: 'info',
            title: `Unusual Log Size: ${dut.id}`,
            description: `Log size ${formatBytes(dut.log_size)} is ${dut.log_size > logMed ? 'significantly larger' : 'significantly smaller'} than median (${formatBytes(logMed)}, ${ratio.toFixed(1)}x).`,
            dutId: dut.id,
            value: dut.log_size,
            threshold: logMed,
          })
        }
      }
    }
  }

  // ──────────────────────────────────────────────────
  // 6. Cross-DUT status inconsistency
  // ──────────────────────────────────────────────────
  if (manifest.duts.length > 1) {
    const collectorStatusMap = new Map<string, Map<string, string>>()
    for (const dut of manifest.duts) {
      for (const g of dut.collector_groups) {
        for (const c of g.collectors) {
          if (String(c.status) === 'not_ran') continue
          if (!collectorStatusMap.has(c.id)) collectorStatusMap.set(c.id, new Map())
          collectorStatusMap.get(c.id)!.set(dut.id, c.status)
        }
      }
    }

    for (const [collectorId, dutStatuses] of collectorStatusMap) {
      if (dutStatuses.size < 2) continue
      const statuses = [...dutStatuses.values()]
      const hasSuccess = statuses.includes('success')
      const hasError = statuses.includes('error')
      if (!hasSuccess || !hasError) continue

      const failedDuts = [...dutStatuses.entries()].filter(([, s]) => s === 'error').map(([d]) => d)
      const passedDuts = [...dutStatuses.entries()].filter(([, s]) => s === 'success').map(([d]) => d)

      for (const fd of failedDuts) {
        pushAnomaly({
          type: 'cross_dut_inconsistency',
          severity: 'warning',
          title: `Inconsistent: ${collectorId}`,
          description: `${collectorId} failed on ${fd} but succeeded on ${passedDuts.slice(0, 3).join(', ')}${passedDuts.length > 3 ? ` +${passedDuts.length - 3} more` : ''}.`,
          dutId: fd,
          collectorId,
          value: failedDuts.length,
          threshold: 0,
        })
      }
    }
  }

  // ──────────────────────────────────────────────────
  // 7. Execution gaps — large idle periods between
  //    consecutive collectors on a single DUT.
  // ──────────────────────────────────────────────────
  const GAP_ABSOLUTE_MIN = 30
  const GAP_CRITICAL_MIN = 300

  for (const pd of manifest.timing?.per_dut ?? []) {
    const sorted = [...pd.collectors]
      .filter(c => c.start_time && c.end_time)
      .sort((a, b) => new Date(a.start_time!).getTime() - new Date(b.start_time!).getTime())

    if (sorted.length < 2) continue

    const gaps: number[] = []
    for (let i = 0; i < sorted.length - 1; i++) {
      const endMs = new Date(sorted[i].end_time!).getTime()
      const nextStartMs = new Date(sorted[i + 1].start_time!).getTime()
      const gapSec = (nextStartMs - endMs) / 1000
      if (gapSec > 0) gaps.push(gapSec)
    }

    if (gaps.length === 0) continue
    const gapMedian = ssMedian(gaps)
    const gapThreshold = Math.max(gapMedian * 3, GAP_ABSOLUTE_MIN)

    for (let i = 0; i < sorted.length - 1; i++) {
      const endMs = new Date(sorted[i].end_time!).getTime()
      const nextStartMs = new Date(sorted[i + 1].start_time!).getTime()
      const gapSec = (nextStartMs - endMs) / 1000
      if (gapSec > gapThreshold) {
        pushAnomaly({
          type: 'execution_gap',
          severity: gapSec > GAP_CRITICAL_MIN ? 'critical' : 'warning',
          title: `Execution Gap: ${pd.dut_id}`,
          description: `${gapSec.toFixed(0)}s idle gap on ${pd.dut_id} between ${sorted[i].id} and ${sorted[i + 1].id} (median gap: ${gapMedian.toFixed(1)}s, threshold: ${gapThreshold.toFixed(0)}s).`,
          dutId: pd.dut_id,
          collectorId: sorted[i + 1].id,
          value: gapSec,
          threshold: gapThreshold,
        })
      }
    }
  }

  return anomalies.sort((a, b) => {
    const sevOrder = { critical: 0, warning: 1, info: 2 }
    return sevOrder[a.severity] - sevOrder[b.severity]
  })
}

function formatBytes(b: number): string {
  if (b < 1024) return b + ' B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB'
  return (b / (1024 * 1024)).toFixed(1) + ' MB'
}

export function getAnomalySummary(anomalies: Anomaly[]): { critical: number; warning: number; info: number } {
  const summary = { critical: 0, warning: 0, info: 0 }
  for (const a of anomalies) summary[a.severity]++
  return summary
}
