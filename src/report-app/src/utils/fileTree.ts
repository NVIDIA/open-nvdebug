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

import type { FileEntry } from '@/types/manifest'

export interface FileTreeNode {
  name: string
  path: string
  depth: number
  children?: FileTreeNode[]
  childCount?: number
  filePath?: string
  fileType?: string
  fileSize?: number
}

interface FileLeaf {
  name: string
  path: string
  type?: string
  size?: number
}

interface DirectoryNode {
  directories: Map<string, DirectoryNode>
  files: FileLeaf[]
  fileCount: number
}

interface FileCandidate {
  segments: string[]
  leaf: FileLeaf
}

const MAX_PATH_LENGTH = 4096
const MAX_PATH_SEGMENTS = 256
const MAX_SEGMENT_LENGTH = 255

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!
    if (codePoint <= 0x1f || codePoint === 0x7f) return true
  }
  return false
}

function newDirectory(): DirectoryNode {
  return {
    directories: new Map<string, DirectoryNode>(),
    files: [],
    fileCount: 0,
  }
}

/**
 * Validate a bundle-relative report path before using any segment as a tree key.
 *
 * Prototype-sensitive names such as `__proto__` are valid file names. They are
 * safe because the tree is Map-backed and never performs dynamic object writes.
 */
export function reportPathSegments(path: unknown): string[] | null {
  if (
    typeof path !== 'string' ||
    !path ||
    path.length > MAX_PATH_LENGTH ||
    path.includes('\\')
  ) {
    return null
  }

  const segments = path.split('/')
  if (segments.length > MAX_PATH_SEGMENTS) return null
  for (const segment of segments) {
    if (
      !segment ||
      segment === '.' ||
      segment === '..' ||
      segment.length > MAX_SEGMENT_LENGTH ||
      hasControlCharacter(segment)
    ) {
      return null
    }
  }
  return segments
}

function asFileCandidate(value: unknown): FileCandidate | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null

  const file = value as Partial<FileEntry>
  const segments = reportPathSegments(file.path)
  if (!segments) return null

  return {
    segments,
    leaf: {
      name: segments[segments.length - 1],
      path: file.path as string,
      type: typeof file.type === 'string' ? file.type : undefined,
      size: typeof file.size === 'number' && Number.isFinite(file.size) ? file.size : undefined,
    },
  }
}

function preferredDuplicate(
  left: FileCandidate,
  right: FileCandidate,
): FileCandidate {
  const leftType = left.leaf.type ?? ''
  const rightType = right.leaf.type ?? ''
  if (leftType !== rightType) return leftType < rightType ? left : right

  const leftSize = left.leaf.size ?? Number.POSITIVE_INFINITY
  const rightSize = right.leaf.size ?? Number.POSITIVE_INFINITY
  return leftSize <= rightSize ? left : right
}

function collisionFreeCandidates(files: readonly unknown[]): FileCandidate[] {
  const byPath = new Map<string, FileCandidate>()
  for (const value of files) {
    const candidate = asFileCandidate(value)
    if (!candidate) continue

    const existing = byPath.get(candidate.leaf.path)
    byPath.set(
      candidate.leaf.path,
      existing ? preferredDuplicate(existing, candidate) : candidate,
    )
  }

  // A physical bundle cannot contain both a file at `a` and another file under
  // `a/`. Prefer the descendant subtree and omit the conflicting prefix file.
  // Computing all directory prefixes first makes the result input-order neutral.
  const directoryPaths = new Set<string>()
  for (const candidate of byPath.values()) {
    let directoryPath = ''
    for (const segment of candidate.segments.slice(0, -1)) {
      directoryPath = directoryPath ? `${directoryPath}/${segment}` : segment
      directoryPaths.add(directoryPath)
    }
  }

  return [...byPath.values()].filter(candidate => !directoryPaths.has(candidate.leaf.path))
}

function buildNodes(
  directory: DirectoryNode,
  parentPath: string,
  depth: number,
): FileTreeNode[] {
  const nodes: FileTreeNode[] = []
  const directories = [...directory.directories.entries()].sort(([left], [right]) =>
    left.localeCompare(right),
  )

  for (const [name, child] of directories) {
    const path = parentPath ? `${parentPath}/${name}` : name
    nodes.push({
      name,
      path,
      depth,
      children: buildNodes(child, path, depth + 1),
      childCount: child.fileCount,
    })
  }

  const files = [...directory.files].sort((left, right) => left.name.localeCompare(right.name))
  for (const file of files) {
    nodes.push({
      name: file.name,
      path: parentPath ? `${parentPath}/${file.name}` : file.name,
      depth,
      filePath: file.path,
      fileType: file.type,
      fileSize: file.size,
    })
  }

  return nodes
}

/** Build a renderable file tree without writing untrusted path keys to objects. */
export function buildFileTree(files: readonly unknown[]): FileTreeNode[] {
  const root = newDirectory()

  for (const { segments, leaf } of collisionFreeCandidates(files)) {
    let current = root
    current.fileCount += 1
    for (const segment of segments.slice(0, -1)) {
      let child = current.directories.get(segment)
      if (!child) {
        child = newDirectory()
        current.directories.set(segment, child)
      }
      current = child
      current.fileCount += 1
    }
    current.files.push(leaf)
  }

  return buildNodes(root, '', 0)
}
