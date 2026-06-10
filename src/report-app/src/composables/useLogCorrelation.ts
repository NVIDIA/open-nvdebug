export type LogCategory =
  | 'redfish' | 'ssh' | 'ipmi' | 'host' | 'bmc' | 'health_check' | 'general'

export interface CorrelationEvent {
  timestamp: number
  source: string
  sourceIndex: number
  line: string
  lineNumber: number
  level?: string
  category: LogCategory
}

const COLLECTOR_PREFIX_MAP: Record<string, LogCategory> = {
  R: 'redfish',
  S: 'ssh',
  I: 'ipmi',
  H: 'host',
  B: 'bmc',
  C: 'health_check',
}

export function categoryFromCollectorId(collectorId: string | undefined): LogCategory {
  if (!collectorId) return 'general'
  const prefix = collectorId.charAt(0).toUpperCase()
  return COLLECTOR_PREFIX_MAP[prefix] ?? 'general'
}

export function categoryFromGroupName(groupName: string | undefined): LogCategory {
  if (!groupName) return 'general'
  const lower = groupName.toLowerCase()
  if (lower === 'redfish') return 'redfish'
  if (lower === 'ssh' || lower === 'bmc_ssh') return 'ssh'
  if (lower === 'ipmi') return 'ipmi'
  if (lower === 'host') return 'host'
  if (lower === 'bmc') return 'bmc'
  if (lower === 'health_check') return 'health_check'
  return 'general'
}

export const CATEGORY_COLORS: Record<LogCategory, string> = {
  redfish: 'var(--nv-service-redfish)',
  ssh: 'var(--nv-service-ssh)',
  ipmi: 'var(--nv-service-ipmi)',
  host: 'var(--nv-service-host)',
  bmc: 'var(--nv-service-bmc)',
  health_check: 'var(--nv-service-health-check)',
  general: 'var(--nv-chart-slate)',
}

export const CATEGORY_LABELS: Record<LogCategory, string> = {
  redfish: 'Redfish',
  ssh: 'SSH / BMC',
  ipmi: 'IPMI',
  host: 'Host',
  bmc: 'BMC',
  health_check: 'Health Check',
  general: 'General',
}

const FORMATS = [
  { pattern: /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/, parse: (m: string) => new Date(m.replace(' ', 'T')).getTime() },
  { pattern: /\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]/, parse: (m: string) => new Date(m.replace(' ', 'T')).getTime() },
  { pattern: /\[\s*(\d+\.\d+)\]/, parse: (m: string) => parseFloat(m) * 1000 },
  { pattern: /((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2})/, parse: (m: string) => new Date(`${m} ${new Date().getFullYear()}`).getTime() },
]

export function parseTimestamp(line: string): number | null {
  for (const fmt of FORMATS) {
    const match = line.match(fmt.pattern)
    if (match) {
      try {
        const ts = fmt.parse(match[1])
        if (!isNaN(ts) && ts > 0) return ts
      } catch { /* skip */ }
    }
  }
  return null
}

export function parseLevel(line: string): string | undefined {
  const match = line.match(/\[(ERROR|WARNING|WARN|INFO|DEBUG|CRITICAL|NOTICE)\]/i)
  return match ? match[1].toUpperCase() : undefined
}

export function correlateFiles(
  files: Array<{ path: string; content: string; index: number; category?: LogCategory }>
): CorrelationEvent[] {
  const events: CorrelationEvent[] = []

  for (const file of files) {
    const cat = file.category ?? 'general'
    const lines = file.content.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      if (!line.trim()) continue
      const ts = parseTimestamp(line)
      if (ts !== null) {
        events.push({
          timestamp: ts,
          source: file.path,
          sourceIndex: file.index,
          line: line.slice(0, 300),
          lineNumber: i + 1,
          level: parseLevel(line),
          category: cat,
        })
      }
    }
  }

  return events.sort((a, b) => a.timestamp - b.timestamp)
}
