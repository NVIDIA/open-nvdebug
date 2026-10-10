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

export const ERROR_CLUSTER_MESSAGE_LIMIT = 200
export const ERROR_CLUSTER_INPUT_LIMIT = 500

const REQUIRED_ERROR_FIELDS = [
  'dut_id',
  'collector_id',
  'collector_name',
  'collector_group',
  'message',
  'timestamp',
] as const

type ErrorEntryDescriptors = Record<typeof REQUIRED_ERROR_FIELDS[number], PropertyDescriptor>

function plainDataDescriptors(value: unknown): ErrorEntryDescriptors | null {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return null

    const descriptors = Object.create(null) as ErrorEntryDescriptors
    for (const field of REQUIRED_ERROR_FIELDS) {
      const descriptor = Object.getOwnPropertyDescriptor(value, field)
      if (descriptor?.enumerable !== true || !('value' in descriptor)) return null
      descriptors[field] = descriptor
    }
    return descriptors
  } catch {
    // Revoked or hostile proxies must not turn malformed report data into a UI crash.
    return null
  }
}

function boundedText(value: unknown, limit = ERROR_CLUSTER_MESSAGE_LIMIT): string {
  if (typeof value === 'string') return value.slice(0, limit)
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return ''
}

/**
 * Convert an untrusted manifest value into the small, data-only shape consumed
 * by error views. Accessors, arrays, exotic prototypes, and throwing proxies
 * are rejected without reading attacker-controlled properties.
 */
export function normalizeErrorEntry(
  value: unknown,
  messageLimit = ERROR_CLUSTER_MESSAGE_LIMIT,
): ErrorEntry | null {
  const descriptors = plainDataDescriptors(value)
  if (!descriptors) return null

  const timestamp = descriptors.timestamp.value
  return {
    dut_id: boundedText(descriptors.dut_id.value),
    collector_id: boundedText(descriptors.collector_id.value),
    collector_name: boundedText(descriptors.collector_name.value),
    collector_group: boundedText(descriptors.collector_group.value),
    message: boundedText(descriptors.message.value, messageLimit),
    timestamp: typeof timestamp === 'string'
      ? timestamp.slice(0, ERROR_CLUSTER_MESSAGE_LIMIT)
      : null,
  }
}

export function normalizeErrorEntries(
  value: unknown,
  messageLimit = ERROR_CLUSTER_MESSAGE_LIMIT,
): ErrorEntry[] {
  try {
    if (!Array.isArray(value)) return []
  } catch {
    return []
  }

  const normalized: ErrorEntry[] = []
  let length: unknown
  try {
    length = value.length
  } catch {
    return normalized
  }
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) {
    return normalized
  }
  const boundedLength = Math.min(length, ERROR_CLUSTER_INPUT_LIMIT)
  for (let index = 0; index < boundedLength; index++) {
    let entry: unknown
    try {
      entry = value[index]
    } catch {
      continue
    }
    const candidate = normalizeErrorEntry(entry, messageLimit)
    if (candidate) normalized.push(candidate)
  }
  return normalized
}
