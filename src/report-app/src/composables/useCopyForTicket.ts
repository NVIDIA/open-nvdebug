import type { DUT, CollectorResult, ErrorEntry } from '@/types/manifest'

export function formatDutForTicket(dut: DUT): string {
  const lines: string[] = []
  lines.push(`DUT: ${dut.id} | Baseboard: ${dut.baseboard} | Status: ${dut.overall_status.toUpperCase()}`)
  if (dut.system_info) {
    const si = dut.system_info
    if (si.model) lines.push(`Model: ${si.model} | Part#: ${si.part_number ?? '—'} | Serial: ${si.serial_number ?? '—'}`)
    if (si.firmware.length > 0) {
      lines.push(`Firmware: ${si.firmware.map(f => `${f.component}: ${f.version}`).join(' | ')}`)
    }
  }
  const s = dut.status_summary
  lines.push(`Collectors: ${s.success} passed, ${s.error} failed, ${s.partial} partial, ${s.skipped} skipped`)
  lines.push(`Execution Time: ${dut.execution_time.toFixed(1)}s | Log Size: ${formatBytes(dut.log_size)}`)

  // List errors
  return lines.join('\n')
}

export function formatCollectorForTicket(dut: DUT, group: string, collector: CollectorResult): string {
  const lines: string[] = []
  lines.push(`Collector: ${collector.id} — ${collector.name}`)
  lines.push(`DUT: ${dut.id} | Group: ${group} | Status: ${collector.status.toUpperCase()}`)
  lines.push(`Duration: ${collector.execution_time.toFixed(1)}s`)
  if (collector.reason) lines.push(`Reason: ${collector.reason}`)
  if (collector.files.length > 0) {
    lines.push(`Files: ${collector.files.map(f => f.path.split('/').pop()).join(', ')}`)
  }
  return lines.join('\n')
}

export function formatErrorForTicket(error: ErrorEntry, dutInfo?: string): string {
  const lines: string[] = []
  lines.push(`Error: ${error.message}`)
  lines.push(`DUT: ${error.dut_id} | Collector: ${error.collector_id} (${error.collector_name}) | Group: ${error.collector_group}`)
  if (error.timestamp) lines.push(`Time: ${error.timestamp}`)
  if (dutInfo) lines.push(dutInfo)
  return lines.join('\n')
}

import { copyToClipboard as _copy } from '@/utils/clipboard'

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await _copy(text)
    return true
  } catch {
    return false
  }
}

function formatBytes(b: number): string {
  if (b < 1024) return b + 'B'
  if (b < 1024 * 1024) return (b / 1024).toFixed(0) + 'KB'
  return (b / (1024 * 1024)).toFixed(1) + 'MB'
}
