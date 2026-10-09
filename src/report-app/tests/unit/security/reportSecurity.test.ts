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

import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const APP_ROOT = process.cwd()

function sourceFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(root, entry.name)
    if (entry.isDirectory()) return sourceFiles(path)
    return /\.(?:ts|vue)$/.test(entry.name) ? [path] : []
  })
}

describe('offline report browser security policy', () => {
  it('ships a restrictive CSP that still permits inlined offline assets', () => {
    const source = readFileSync(resolve(APP_ROOT, 'index.html'), 'utf8')

    expect(source).toContain('http-equiv="Content-Security-Policy"')
    expect(source).toContain("default-src 'none'")
    expect(source).toContain("connect-src 'self' blob:")
    expect(source).toContain("object-src 'none'")
    expect(source).toContain("base-uri 'none'")
    expect(source).toContain("form-action 'none'")
    expect(source).toContain('<meta name="referrer" content="no-referrer" />')
  })

  it('does not include the rasterizing html2pdf dependency', () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(APP_ROOT, 'package.json'), 'utf8'),
    ) as { dependencies?: Record<string, string> }
    const lockSource = readFileSync(resolve(APP_ROOT, 'package-lock.json'), 'utf8')

    expect(packageJson.dependencies).not.toHaveProperty('html2pdf.js')
    expect(lockSource).not.toContain('node_modules/html2pdf.js')
    expect(lockSource).not.toContain('node_modules/html2canvas')
  })

  it('uses named route builders for all data-derived DUT links', () => {
    const unsafeRoutes = sourceFiles(resolve(APP_ROOT, 'src'))
      .filter(path => !path.endsWith('/router/index.ts'))
      .flatMap((path) => {
        const source = readFileSync(path, 'utf8')
        return source.includes('/dut/${') || /['"]\/dut\/['"]\s*\+/.test(source)
          ? [path]
          : []
      })

    expect(unsafeRoutes).toEqual([])
  })
})
