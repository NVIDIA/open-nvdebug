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

import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
} from 'node:fs'
import { posix, resolve, sep } from 'node:path'
import { TextDecoder } from 'node:util'

export const REPORT_APP_SOURCE_META_NAME = 'nvdebug-report-app-source-sha256'

const INPUT_MANIFEST_NAME = 'report-app-inputs.json'
const DIGEST_DOMAIN = 'nvdebug-report-app-source-v1\n'
const MAX_INPUT_MANIFEST_BYTES = 64 * 1024
const MAX_SOURCE_INPUT_FILES = 4096
const MAX_SOURCE_INPUT_BYTES = 64 * 1024 * 1024
const STABLE_FILE_FIELDS = [
  'dev',
  'ino',
  'mode',
  'size',
  'mtimeNs',
  'ctimeNs',
]
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true })

function sameFile(first, second) {
  return STABLE_FILE_FIELDS.every(field => first[field] === second[field])
}

function readStableRegularFile(path, maximumBytes) {
  const before = lstatSync(path, { bigint: true })
  if (!before.isFile() || before.isSymbolicLink() || before.size > BigInt(maximumBytes)) {
    throw new Error('Report-app input is not a bounded regular file')
  }

  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const opened = fstatSync(descriptor, { bigint: true })
    if (!sameFile(before, opened)) {
      throw new Error('Report-app input changed before it was opened')
    }

    const chunks = []
    let observed = 0
    while (true) {
      const remaining = maximumBytes + 1 - observed
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, remaining))
      const count = readSync(descriptor, chunk, 0, chunk.length, null)
      if (count === 0) {
        break
      }
      chunks.push(chunk.subarray(0, count))
      observed += count
      if (observed > maximumBytes) {
        throw new Error('Report-app input exceeds its byte bound')
      }
    }

    const after = fstatSync(descriptor, { bigint: true })
    const pathAfter = lstatSync(path, { bigint: true })
    if (
      BigInt(observed) !== before.size
      || !sameFile(before, after)
      || !sameFile(before, pathAfter)
    ) {
      throw new Error('Report-app input changed while it was read')
    }
    return Buffer.concat(chunks, observed)
  } finally {
    closeSync(descriptor)
  }
}

function requireRelativePath(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\\')
    || posix.isAbsolute(value)
  ) {
    throw new Error(`Invalid report-app ${label}`)
  }
  if (UTF8_DECODER.decode(Buffer.from(value, 'utf8')) !== value) {
    throw new Error(`Invalid report-app ${label}`)
  }
  const normalized = posix.normalize(value)
  if (
    normalized !== value
    || normalized.endsWith('/')
    || normalized === '.'
    || normalized === '..'
    || normalized.startsWith('../')
  ) {
    throw new Error(`Invalid report-app ${label}`)
  }
  return normalized
}

function requireWithinRoot(root, relativePath) {
  const components = relativePath.split('/')
  const candidate = resolve(root, ...components)
  if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) {
    throw new Error('Report-app input escaped its source root')
  }
  for (let index = 1; index < components.length; index += 1) {
    const parent = resolve(root, ...components.slice(0, index))
    const metadata = lstatSync(parent)
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error('Report-app input parent is not a regular directory')
    }
  }
  return candidate
}

function loadInputManifest(root) {
  const path = requireWithinRoot(root, INPUT_MANIFEST_NAME)
  const document = JSON.parse(
    UTF8_DECODER.decode(readStableRegularFile(path, MAX_INPUT_MANIFEST_BYTES)),
  )
  if (
    document === null
    || typeof document !== 'object'
    || Array.isArray(document)
    || Object.keys(document).sort().join(',') !== 'directories,files,schema_version'
    || document.schema_version !== 1
    || !Array.isArray(document.files)
    || !Array.isArray(document.directories)
  ) {
    throw new Error('Report-app input manifest is malformed')
  }
  const files = document.files.map(
    value => requireRelativePath(value, 'file input'),
  )
  const directories = document.directories.map(
    value => requireRelativePath(value, 'directory input'),
  )
  if (new Set(files).size !== files.length || new Set(directories).size !== directories.length) {
    throw new Error('Report-app input manifest contains duplicates')
  }
  return { files, directories }
}

function collectDirectory(root, relativeDirectory, inputs) {
  const directory = requireWithinRoot(root, relativeDirectory)
  const before = lstatSync(directory, { bigint: true })
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new Error('Report-app source input is not a regular directory')
  }
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const relativePath = posix.join(relativeDirectory, entry.name)
    if (entry.isSymbolicLink()) {
      throw new Error('Report-app source inputs must not contain symbolic links')
    }
    if (entry.isDirectory()) {
      collectDirectory(root, relativePath, inputs)
    } else if (entry.isFile()) {
      if (inputs.has(relativePath)) {
        throw new Error('Report-app input manifest contains overlaps')
      }
      inputs.add(relativePath)
      if (inputs.size > MAX_SOURCE_INPUT_FILES) {
        throw new Error('Report-app source input inventory exceeds its entry bound')
      }
    } else {
      throw new Error('Report-app source inputs must be regular files')
    }
  }
  const after = lstatSync(directory, { bigint: true })
  if (
    before.dev !== after.dev
    || before.ino !== after.ino
    || before.mode !== after.mode
  ) {
    throw new Error('Report-app source directory changed during inventory')
  }
}

export function computeReportAppSourceDigest(reportAppRoot) {
  const root = resolve(reportAppRoot)
  const rootMetadata = lstatSync(root)
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error('Report-app source root is not a regular directory')
  }

  const manifest = loadInputManifest(root)
  const inputs = new Set(manifest.files)
  if (inputs.size > MAX_SOURCE_INPUT_FILES) {
    throw new Error('Report-app source input inventory exceeds its entry bound')
  }
  for (const relativeDirectory of manifest.directories) {
    collectDirectory(root, relativeDirectory, inputs)
  }

  const aggregate = createHash('sha256')
  aggregate.update(DIGEST_DOMAIN, 'utf8')
  let totalBytes = 0
  const sortedInputs = [...inputs].sort((first, second) => (
    Buffer.compare(Buffer.from(first, 'utf8'), Buffer.from(second, 'utf8'))
  ))
  for (const relativePath of sortedInputs) {
    const path = requireWithinRoot(root, relativePath)
    const payload = readStableRegularFile(path, MAX_SOURCE_INPUT_BYTES)
    totalBytes += payload.length
    if (totalBytes > MAX_SOURCE_INPUT_BYTES) {
      throw new Error('Report-app source inputs exceed their aggregate byte bound')
    }
    const relativeBytes = Buffer.byteLength(relativePath, 'utf8')
    const leafDigest = createHash('sha256').update(payload).digest('hex')
    aggregate.update(
      `${relativeBytes}:${relativePath}:${payload.length}:${leafDigest}\n`,
      'utf8',
    )
  }
  return aggregate.digest('hex')
}
