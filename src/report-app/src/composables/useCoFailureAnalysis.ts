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

import type { Manifest } from '@/types/manifest'

export interface FailureCluster {
  id: number
  collectors: string[]
  dutIds: string[]
  coOccurrences: number
  sharedService: string | null
  sharedDependency: string | null
}

export interface CoFailurePair {
  a: string
  b: string
  coCount: number
  jaccard: number
  dutIds: string[]
}

export interface CoFailureResult {
  pairs: CoFailurePair[]
  clusters: FailureCluster[]
  limited: boolean
  limitReason: string | null
}

export const MAX_CO_FAILURE_PAIR_OBSERVATIONS = 100_000

export function analyzeCoFailures(manifest: Manifest): CoFailureResult {
  const failedByDut = new Map<string, Set<string>>()
  const collectorServiceMap = new Map<string, string>()
  const collectorDepMap = new Map<string, string[]>()

  for (const dut of manifest.duts) {
    const failed = new Set<string>()
    for (const g of dut.collector_groups) {
      for (const c of g.collectors) {
        if (!collectorServiceMap.has(c.id)) collectorServiceMap.set(c.id, g.service_type || g.name)
        if (!collectorDepMap.has(c.id)) collectorDepMap.set(c.id, c.dependencies ?? [])
        if (c.status === 'error') failed.add(c.id)
      }
    }
    if (failed.size > 0) failedByDut.set(dut.id, failed)
  }

  // Count failing DUTs without allocating one Set per collector. Collectors
  // seen on only one DUT can never meet the two-DUT co-failure threshold.
  const failureDutCounts = new Map<string, number>()
  for (const failed of failedByDut.values()) {
    for (const cid of failed) {
      failureDutCounts.set(cid, (failureDutCounts.get(cid) ?? 0) + 1)
    }
  }

  const pairCandidatesByDut = new Map<string, string[]>()
  let pairObservationCount = 0
  for (const [dutId, failed] of failedByDut) {
    const candidates = [...failed].filter(
      cid => (failureDutCounts.get(cid) ?? 0) >= 2,
    )
    const candidatePairs = candidates.length * (candidates.length - 1) / 2
    if (
      candidatePairs > MAX_CO_FAILURE_PAIR_OBSERVATIONS - pairObservationCount
    ) {
      return {
        pairs: [],
        clusters: [],
        limited: true,
        limitReason:
          `Co-failure analysis skipped because pair work exceeds the ` +
          `${MAX_CO_FAILURE_PAIR_OBSERVATIONS.toLocaleString()}-observation safety limit.`,
      }
    }
    pairObservationCount += candidatePairs
    pairCandidatesByDut.set(dutId, candidates)
  }

  // Co-occurrence counts. The preflight above provides a hard upper bound on
  // both iterations and aggregate dutIds stored across the map.
  const pairCounts = new Map<string, { count: number; dutIds: string[] }>()
  for (const [dutId, arr] of pairCandidatesByDut) {
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        const key = arr[i] < arr[j] ? `${arr[i]}::${arr[j]}` : `${arr[j]}::${arr[i]}`
        if (!pairCounts.has(key)) pairCounts.set(key, { count: 0, dutIds: [] })
        const entry = pairCounts.get(key)!
        entry.count++
        entry.dutIds.push(dutId)
      }
    }
  }

  // Jaccard similarity and pairs
  const pairs: CoFailurePair[] = []
  for (const [key, { count, dutIds }] of pairCounts) {
    if (count < 2) continue
    const [a, b] = key.split('::')
    const unionSize = failureDutCounts.get(a)! + failureDutCounts.get(b)! - count
    const jaccard = count / unionSize
    pairs.push({ a, b, coCount: count, jaccard, dutIds })
  }
  pairs.sort((a, b) => b.jaccard - a.jaccard || b.coCount - a.coCount)

  // Cluster via union-find on high-jaccard pairs
  const parent = new Map<string, string>()
  function find(x: string): string {
    if (!parent.has(x)) parent.set(x, x)
    if (parent.get(x) !== x) parent.set(x, find(parent.get(x)!))
    return parent.get(x)!
  }
  function unite(x: string, y: string) {
    parent.set(find(x), find(y))
  }

  for (const p of pairs) {
    if (p.jaccard >= 0.5) unite(p.a, p.b)
  }

  const clusterMap = new Map<
    string,
    { collectors: Set<string>; dutIds: Set<string>; coOccurrences: number }
  >()
  for (const p of pairs) {
    if (p.jaccard < 0.5) continue
    const root = find(p.a)
    if (!clusterMap.has(root)) {
      clusterMap.set(root, {
        collectors: new Set(),
        dutIds: new Set(),
        coOccurrences: 0,
      })
    }
    const cl = clusterMap.get(root)!
    cl.collectors.add(p.a)
    cl.collectors.add(p.b)
    for (const d of p.dutIds) cl.dutIds.add(d)
  }

  // Account for all pairs within a high-correlation component in one pass.
  // The previous per-cluster scan of every pair was quadratic in pair count.
  for (const p of pairs) {
    const root = find(p.a)
    if (root === find(p.b)) {
      const cluster = clusterMap.get(root)
      if (cluster) cluster.coOccurrences += p.coCount
    }
  }

  let clusterId = 0
  const clusters: FailureCluster[] = []
  for (const cl of clusterMap.values()) {
    if (cl.collectors.size < 2) continue
    const collArr = [...cl.collectors]
    const services = new Set(collArr.map(c => collectorServiceMap.get(c)).filter(Boolean))
    const sharedService = services.size === 1 ? [...services][0]! : null

    // Check shared dependencies
    const depSets = collArr.map(c => new Set(collectorDepMap.get(c) ?? []))
    let sharedDeps = depSets.length > 0 ? new Set(depSets[0]) : new Set<string>()
    for (let i = 1; i < depSets.length; i++) {
      sharedDeps = new Set([...sharedDeps].filter(d => depSets[i].has(d)))
    }
    const sharedDependency = sharedDeps.size > 0 ? [...sharedDeps][0] : null

    clusters.push({
      id: clusterId++,
      collectors: collArr.sort(),
      dutIds: [...cl.dutIds].sort(),
      coOccurrences: cl.coOccurrences,
      sharedService,
      sharedDependency,
    })
  }
  clusters.sort((a, b) => b.coOccurrences - a.coOccurrences)

  return {
    pairs: pairs.slice(0, 50),
    clusters,
    limited: false,
    limitReason: null,
  }
}
