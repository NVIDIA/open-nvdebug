import type { Manifest } from '@/types/manifest'
import { formatDuration } from '@/utils/format'

/**
 * Generate a natural language summary of the report.
 * Deterministic template-based approach (not AI).
 */
export function generateReportSummary(manifest: Manifest): string {
  const summary = manifest.collection_summary
  const lines: string[] = []

  // Header
  lines.push(`Collection Summary — ${manifest.generated_at}`)
  lines.push('')

  // Overview
  lines.push(`${summary.total_duts} DUT(s) collected at level ${manifest.tool_config.collection_level}. Total runtime: ${formatDuration(summary.total_runtime)}.`)
  lines.push('')

  // Status
  const total = summary.total_collectors_executed + summary.status_counts.skipped
  const pct = summary.overall_collection_pct
  lines.push(`Overall: ${summary.status_counts.success}/${total} collectors passed (${pct}%). ${summary.status_counts.error} failed, ${summary.status_counts.partial} partial.`)
  lines.push('')

  // Issues
  if (manifest.errors.length > 0) {
    lines.push('Issues found:')
    // Group errors by DUT
    const byDut = new Map<string, string[]>()
    for (const e of manifest.errors) {
      if (!byDut.has(e.dut_id)) byDut.set(e.dut_id, [])
      byDut.get(e.dut_id)!.push(`${e.collector_id} (${e.collector_name}): ${e.message.slice(0, 80)}`)
    }
    for (const [dutId, errors] of byDut) {
      lines.push(`- ${dutId}: ${errors.length} error(s)`)
      for (const err of errors.slice(0, 3)) {
        lines.push(`  - ${err}`)
      }
      if (errors.length > 3) lines.push(`  - ... and ${errors.length - 3} more`)
    }
    lines.push('')
  }

  // Anomalies (collectors >3x median duration)
  const allDurations: number[] = []
  for (const dut of manifest.duts) {
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (c.execution_time > 0) allDurations.push(c.execution_time)
      }
    }
  }
  if (allDurations.length > 0) {
    const sorted = [...allDurations].sort((a, b) => a - b)
    const median = sorted[Math.floor(sorted.length / 2)]
    const anomalies: string[] = []
    for (const dut of manifest.duts) {
      for (const g of dut.collector_groups) {
        for (const c of g.collectors) {
          if (c.execution_time > median * 3 && c.execution_time > 10) {
            anomalies.push(`${dut.id}: ${c.id} took ${c.execution_time.toFixed(1)}s (median: ${median.toFixed(1)}s) — ${(c.execution_time / median).toFixed(1)}x slower`)
          }
        }
      }
    }
    if (anomalies.length > 0) {
      lines.push('Anomalies:')
      for (const a of anomalies.slice(0, 5)) lines.push(`- ${a}`)
      lines.push('')
    }
  }

  // Firmware
  const firmwareVersions = new Map<string, Set<string>>()
  for (const dut of manifest.duts) {
    for (const fw of dut.system_info?.firmware ?? []) {
      const key = fw.name || fw.id || fw.component || 'unknown'
      if (!firmwareVersions.has(key)) firmwareVersions.set(key, new Set())
      firmwareVersions.get(key)!.add(`${fw.version} (${dut.id})`)
    }
  }
  if (firmwareVersions.size > 0) {
    lines.push('Firmware:')
    for (const [component, versions] of firmwareVersions) {
      if (versions.size === 1) {
        lines.push(`- ${component}: ${[...versions][0].split(' (')[0]} (all DUTs)`)
      } else {
        lines.push(`- ${component}: ${[...versions].join(', ')}`)
      }
    }
  }

  return lines.join('\n')
}
