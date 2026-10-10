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

/** Shared limits for interactive traversal of untrusted report JSON. */
export const MAX_JSON_TREE_DEPTH = 64
export const MAX_JSON_TREE_NODES = 10_000

export interface JsonTreeVisit {
  value: unknown
  path: string
  label?: string
  depth: number
}

export interface JsonTreeWalkResult {
  visitedNodes: number
  truncatedByDepth: boolean
  truncatedByNodes: boolean
}

interface PendingVisit extends JsonTreeVisit {}

/**
 * Visit JSON nodes iteratively while enforcing depth and aggregate node limits.
 *
 * The return value tells the caller whether any content was omitted so the UI
 * can disclose the bounded preview instead of silently presenting it as full.
 */
export function walkJsonTreeBounded(
  root: unknown,
  visit: (node: JsonTreeVisit) => void,
  maxDepth = MAX_JSON_TREE_DEPTH,
  maxNodes = MAX_JSON_TREE_NODES,
): JsonTreeWalkResult {
  const pending: PendingVisit[] = [{ value: root, path: '$', depth: 0 }]
  let visitedNodes = 0
  let truncatedByDepth = false
  let truncatedByNodes = false

  while (pending.length > 0) {
    if (visitedNodes >= maxNodes) {
      truncatedByNodes = true
      break
    }

    const node = pending.pop()!
    visitedNodes += 1
    visit(node)

    if (node.value === null || typeof node.value !== 'object') continue
    const entries = Object.entries(node.value)
    if (node.depth >= maxDepth) {
      if (entries.length > 0) truncatedByDepth = true
      continue
    }

    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const [key, value] = entries[index]
      pending.push({
        value,
        path: `${node.path}.${key}`,
        label: key,
        depth: node.depth + 1,
      })
    }
  }

  return { visitedNodes, truncatedByDepth, truncatedByNodes }
}

/** Return an operator-facing explanation when a JSON walk was bounded. */
export function jsonTreeTruncationNotice(result: JsonTreeWalkResult): string {
  const limits: string[] = []
  if (result.truncatedByDepth) limits.push(`depth ${MAX_JSON_TREE_DEPTH}`)
  if (result.truncatedByNodes) limits.push(`${MAX_JSON_TREE_NODES.toLocaleString()} nodes`)
  if (limits.length === 0) return ''
  return `JSON preview traversal stopped at ${limits.join(' and ')}; download the artifact to inspect omitted content.`
}
