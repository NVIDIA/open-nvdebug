import type { ErrorEntry } from '@/types/manifest'

export interface ErrorCluster {
  id: number
  representative: string
  count: number
  entries: ErrorEntry[]
  dutIds: string[]
  collectorIds: string[]
  severity: 'critical' | 'high' | 'medium' | 'low'
  knownIssue: KnownIssue | null
}

export interface KnownIssue {
  pattern: string
  title: string
  description: string
  fix: string
}

const KNOWN_ISSUES: KnownIssue[] = [
  {
    pattern: 'connection refused',
    title: 'Connection Refused',
    description: 'The target service is not accepting connections on the expected port.',
    fix: 'Verify the BMC/host is powered on and the service (Redfish, SSH, IPMI) is running. Check firewall rules.',
  },
  {
    pattern: 'timeout|timed out',
    title: 'Request Timeout',
    description: 'The request took too long and was terminated.',
    fix: 'Check network connectivity to the DUT. Increase timeout via --timeout flag if the device is slow to respond.',
  },
  {
    pattern: 'authentication|401|403|unauthorized|forbidden',
    title: 'Authentication Failure',
    description: 'Credentials were rejected or insufficient permissions.',
    fix: 'Verify BMC credentials in the DUT config file. Ensure the user account has sufficient privileges.',
  },
  {
    pattern: 'no route to host|network unreachable',
    title: 'Network Unreachable',
    description: 'The DUT is not reachable on the network.',
    fix: 'Check that the BMC IP is correct and reachable from this host. Verify VLAN/subnet configuration.',
  },
  {
    pattern: 'ssl|certificate|tls',
    title: 'SSL/TLS Error',
    description: 'Certificate validation failed or TLS handshake error.',
    fix: 'Use --no-verify-ssl to skip certificate validation, or install the correct CA certificate.',
  },
  {
    pattern: 'disk space|no space left',
    title: 'Disk Space Exhausted',
    description: 'The local disk ran out of space during collection.',
    fix: 'Free disk space on the collection host. Log files can be large for multi-DUT collections.',
  },
  {
    pattern: 'command not found|not recognized',
    title: 'Missing Command',
    description: 'A required system command was not found on the BMC or host.',
    fix: 'Verify the target platform firmware version supports the expected commands.',
  },
]

function levenshteinDistance(a: string, b: string): number {
  const maxLen = 200
  const sa = a.slice(0, maxLen)
  const sb = b.slice(0, maxLen)
  const la = sa.length
  const lb = sb.length

  if (la === 0) return lb
  if (lb === 0) return la

  let prev = new Uint16Array(lb + 1)
  let curr = new Uint16Array(lb + 1)

  for (let j = 0; j <= lb; j++) prev[j] = j

  for (let i = 1; i <= la; i++) {
    curr[0] = i
    for (let j = 1; j <= lb; j++) {
      const cost = sa[i - 1] === sb[j - 1] ? 0 : 1
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
    }
    ;[prev, curr] = [curr, prev]
  }

  return prev[lb]
}

function similarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length, 1)
  return 1 - levenshteinDistance(a, b) / maxLen
}

function normalizeMessage(msg: string): string {
  return msg
    .replace(/0x[0-9a-fA-F]+/g, '0xHEX')
    .replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, 'IP_ADDR')
    .replace(/\b[0-9a-f]{8,}\b/gi, 'HASH')
    .replace(/\d+\.\d+s/g, 'N.Ns')
    .replace(/\d+/g, 'N')
    .trim()
}

function matchKnownIssue(msg: string): KnownIssue | null {
  const lower = msg.toLowerCase()
  for (const issue of KNOWN_ISSUES) {
    if (new RegExp(issue.pattern, 'i').test(lower)) return issue
  }
  return null
}

function classifySeverity(cluster: { count: number; dutIds: string[] }): ErrorCluster['severity'] {
  if (cluster.dutIds.length > 3 || cluster.count > 10) return 'critical'
  if (cluster.dutIds.length > 1 || cluster.count > 5) return 'high'
  if (cluster.count > 2) return 'medium'
  return 'low'
}

export function clusterErrors(errors: ErrorEntry[], threshold = 0.6): ErrorCluster[] {
  if (errors.length === 0) return []

  const clusters: ErrorCluster[] = []
  const assigned = new Set<number>()

  for (let i = 0; i < errors.length; i++) {
    if (assigned.has(i)) continue

    const cluster: ErrorEntry[] = [errors[i]]
    const normI = normalizeMessage(errors[i].message)
    assigned.add(i)

    for (let j = i + 1; j < errors.length; j++) {
      if (assigned.has(j)) continue
      const normJ = normalizeMessage(errors[j].message)
      if (similarity(normI, normJ) >= threshold) {
        cluster.push(errors[j])
        assigned.add(j)
      }
    }

    const dutIds = [...new Set(cluster.map(e => e.dut_id))]
    const collectorIds = [...new Set(cluster.map(e => e.collector_id))]
    const representative = cluster[0].message

    clusters.push({
      id: clusters.length,
      representative,
      count: cluster.length,
      entries: cluster,
      dutIds,
      collectorIds,
      severity: classifySeverity({ count: cluster.length, dutIds }),
      knownIssue: matchKnownIssue(representative),
    })
  }

  return clusters.sort((a, b) => {
    const sev = { critical: 0, high: 1, medium: 2, low: 3 }
    if (sev[a.severity] !== sev[b.severity]) return sev[a.severity] - sev[b.severity]
    return b.count - a.count
  })
}
