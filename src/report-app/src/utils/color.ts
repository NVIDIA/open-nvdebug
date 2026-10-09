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

/**
 * Normalize any CSS color to a 6-digit hex string (#RRGGBB).
 * Handles shorthand (#fff), 6-digit (#ffffff), rgb(), rgba(), and empty strings.
 * Returns fallback if parsing fails.
 */
export function toHex6(color: string, fallback = '#888888'): string {
  const c = color.trim()
  if (!c) return fallback

  if (c.startsWith('#')) {
    const hex = c.slice(1)
    if (hex.length === 3) {
      return '#' + hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2]
    }
    if (hex.length >= 6) {
      return '#' + hex.slice(0, 6)
    }
    return fallback
  }

  const rgbMatch = c.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/)
  if (rgbMatch) {
    const r = parseInt(rgbMatch[1]).toString(16).padStart(2, '0')
    const g = parseInt(rgbMatch[2]).toString(16).padStart(2, '0')
    const b = parseInt(rgbMatch[3]).toString(16).padStart(2, '0')
    return `#${r}${g}${b}`
  }

  return fallback
}
