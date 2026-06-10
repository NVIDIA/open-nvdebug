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
}

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

  // Co-occurrence counts
  const pairCounts = new Map<string, { count: number; dutIds: string[] }>()
  const failSets = new Map<string, Set<string>>()

  for (const [dutId, failed] of failedByDut) {
    for (const cid of failed) {
      if (!failSets.has(cid)) failSets.set(cid, new Set())
      failSets.get(cid)!.add(dutId)
    }

    const arr = [...failed]
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
    const setA = failSets.get(a)!
    const setB = failSets.get(b)!
    const union = new Set([...setA, ...setB])
    const jaccard = count / union.size
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

  const clusterMap = new Map<string, { collectors: Set<string>; dutIds: Set<string> }>()
  for (const p of pairs) {
    if (p.jaccard < 0.5) continue
    const root = find(p.a)
    if (!clusterMap.has(root)) clusterMap.set(root, { collectors: new Set(), dutIds: new Set() })
    const cl = clusterMap.get(root)!
    cl.collectors.add(p.a)
    cl.collectors.add(p.b)
    for (const d of p.dutIds) cl.dutIds.add(d)
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

    // Total co-occurrences
    let total = 0
    for (const p of pairs) {
      if (cl.collectors.has(p.a) && cl.collectors.has(p.b)) total += p.coCount
    }

    clusters.push({
      id: clusterId++,
      collectors: collArr.sort(),
      dutIds: [...cl.dutIds].sort(),
      coOccurrences: total,
      sharedService,
      sharedDependency,
    })
  }
  clusters.sort((a, b) => b.coOccurrences - a.coOccurrences)

  return { pairs: pairs.slice(0, 50), clusters }
}
