// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type { ErrorEntry } from '@/types/manifest'
import {
  ERROR_CLUSTER_INPUT_LIMIT,
  ERROR_CLUSTER_MESSAGE_LIMIT,
  normalizeErrorEntry,
} from '@/utils/errorEntries'

export { ERROR_CLUSTER_INPUT_LIMIT, ERROR_CLUSTER_MESSAGE_LIMIT }

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

export interface ErrorClusteringResult {
  clusters: ErrorCluster[]
  processedErrors: number
  omittedErrors: number
  comparisons: number
}

// Keep all attacker-controlled work on the UI thread behind explicit ceilings.
export const ERROR_CLUSTER_COMPARISON_LIMIT = 512

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
  const sa = a.slice(0, ERROR_CLUSTER_MESSAGE_LIMIT)
  const sb = b.slice(0, ERROR_CLUSTER_MESSAGE_LIMIT)
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

function boundedMessage(value: unknown): string {
  if (typeof value === 'string') return value.slice(0, ERROR_CLUSTER_MESSAGE_LIMIT)
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return ''
}

function normalizeMessage(msg: unknown): string {
  return boundedMessage(msg)
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

export function clusterErrorsWithStats(
  errors: readonly unknown[],
  threshold = 0.6,
): ErrorClusteringResult {
  let sourceLength = 0
  try {
    if (Array.isArray(errors)) {
      const length: unknown = errors.length
      if (typeof length === 'number' && Number.isSafeInteger(length) && length >= 0) {
        sourceLength = length
      }
    }
  } catch {
    sourceLength = 0
  }

  const boundedErrors: ErrorEntry[] = []
  const boundedLength = Math.min(sourceLength, ERROR_CLUSTER_INPUT_LIMIT)
  for (let index = 0; index < boundedLength; index++) {
    let candidate: unknown
    try {
      candidate = errors[index]
    } catch {
      continue
    }
    const normalized = normalizeErrorEntry(candidate)
    if (normalized) boundedErrors.push(normalized)
  }
  if (boundedErrors.length === 0) {
    return {
      clusters: [],
      processedErrors: 0,
      omittedErrors: Math.max(0, sourceLength - boundedLength),
      comparisons: 0,
    }
  }

  // Collapse exact normalized matches in one pass before spending any fuzzy
  // comparison budget. This retains useful counts for common repeated errors.
  const exactGroups = new Map<
    string,
    { normalized: string; entries: ErrorEntry[] }
  >()
  for (const error of boundedErrors) {
    const normalized = normalizeMessage(error.message)
    const existing = exactGroups.get(normalized)
    if (existing) existing.entries.push(error)
    else exactGroups.set(normalized, { normalized, entries: [error] })
  }

  const mergedGroups: Array<{ normalized: string; entries: ErrorEntry[] }> = []
  const safeThreshold = Number.isFinite(threshold)
    ? Math.min(1, Math.max(0, threshold))
    : 0.6
  let comparisons = 0

  for (const group of exactGroups.values()) {
    let matchedGroup: { normalized: string; entries: ErrorEntry[] } | undefined
    for (const candidate of mergedGroups) {
      if (comparisons >= ERROR_CLUSTER_COMPARISON_LIMIT) break
      comparisons++
      if (similarity(candidate.normalized, group.normalized) >= safeThreshold) {
        matchedGroup = candidate
        break
      }
    }
    if (matchedGroup) matchedGroup.entries.push(...group.entries)
    else mergedGroups.push(group)
  }

  const clusters: ErrorCluster[] = mergedGroups.map(({ entries }, id) => {
    const cluster = entries
    const dutIds = [...new Set(cluster.map(e => e.dut_id))]
    const collectorIds = [...new Set(cluster.map(e => e.collector_id))]
    const representative = boundedMessage(cluster[0].message)

    return {
      id,
      representative,
      count: cluster.length,
      entries: cluster,
      dutIds,
      collectorIds,
      severity: classifySeverity({ count: cluster.length, dutIds }),
      knownIssue: matchKnownIssue(representative),
    }
  })

  clusters.sort((a, b) => {
    const sev = { critical: 0, high: 1, medium: 2, low: 3 }
    if (sev[a.severity] !== sev[b.severity]) return sev[a.severity] - sev[b.severity]
    return b.count - a.count
  })

  return {
    clusters,
    processedErrors: boundedErrors.length,
    omittedErrors: Math.max(0, sourceLength - boundedLength),
    comparisons,
  }
}

export function clusterErrors(errors: readonly unknown[], threshold = 0.6): ErrorCluster[] {
  return clusterErrorsWithStats(errors, threshold).clusters
}
