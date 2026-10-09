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

import { test, expect } from '@playwright/test'
import { createServer, type RequestListener, type Server, type ServerResponse } from 'node:http'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { pathToFileURL } from 'node:url'
import { gzipSync } from 'node:zlib'

const bundle = readFileSync('dist/index.html', 'utf8')
const sample = readFileSync('tests/fixtures/sample_manifest.json', 'utf8')
const marker = '<!-- __NVDEBUG_MANIFEST_PLACEHOLDER__ -->'

async function serve(handler: RequestListener): Promise<{ server: Server; url: string }> {
  const server = createServer(handler)
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('No fixture server port')
  return { server, url: `http://127.0.0.1:${address.port}/` }
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections()
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('nv-tour-completed', 'true'))
})

test('paints the static splash before receiving the payload and bundled assets', async ({ page }) => {
  const offset = bundle.indexOf(marker)
  expect(offset).toBeGreaterThan(bundle.indexOf('id="report-startup"'))
  let response: ServerResponse | undefined
  const { server, url } = await serve((request, res) => {
    if (request.url === '/') {
      response = res
      res.writeHead(200, { 'content-type': 'text/html' })
      res.write(bundle.slice(0, offset))
    } else if (request.url === '/manifest.json') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(sample)
    } else {
      res.writeHead(404).end()
    }
  })
  try {
    await page.goto(url, { waitUntil: 'commit' })
    await expect(page.locator('#report-startup')).toBeVisible()
    await expect(page.getByText('Opening report…')).toBeVisible()
    await expect.poll(() => page.evaluate(() => performance.getEntriesByType('paint').map(entry => entry.name)))
      .toContain('first-contentful-paint')
    response!.end(bundle.slice(offset))
    await expect(page.getByRole('heading', { name: 'NVDebug Collection Report' })).toBeVisible()
    await expect(page.locator('#report-startup')).toHaveCount(0)
  } finally {
    await close(server)
  }
})

test('retains the splash and measured progress while a large HTTP payload is incomplete', async ({ page }) => {
  const bytes = Buffer.from(JSON.stringify({ ...JSON.parse(sample), padding: 'synthetic'.repeat(1_000_000) }))
  const chunkSize = 256 * 1024
  let response: ServerResponse | undefined
  const { server, url } = await serve((request, res) => {
    if (request.url === '/') {
      res.writeHead(200, { 'content-type': 'text/html' }).end(bundle)
    } else if (request.url === '/manifest.json') {
      response = res
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': bytes.byteLength })
      res.write(bytes.subarray(0, chunkSize))
    } else {
      res.writeHead(404).end()
    }
  })
  try {
    await page.goto(url)
    await expect(page.locator('#report-startup-stage')).toHaveText('Reading report data…')
    await expect.poll(() => page.locator('#report-startup-progress').getAttribute('value')).toBe(String(chunkSize))
    await expect(page.locator('#report-startup-progress')).toHaveAttribute('max', String(bytes.byteLength))
    await expect(page.locator('#report-startup')).toBeVisible()
    response!.end(bytes.subarray(chunkSize))
    await expect(page.getByRole('heading', { name: 'NVDebug Collection Report' })).toBeVisible()
    await expect(page.locator('#report-startup')).toHaveCount(0)
  } finally {
    await close(server)
  }
})

test('reports decoding stages when opening a large compressed report directly from disk', async ({ page }) => {
  const directory = mkdtempSync(join(tmpdir(), 'nvdebug-startup-e2e-'))
  const raw = Buffer.from(JSON.stringify({ ...JSON.parse(sample), padding: 'synthetic é'.repeat(500_000) }))
  const compressed = gzipSync(raw)
  const embedded = `<script id="__NVDEBUG_MANIFEST_GZIP__" type="application/octet-stream" data-encoding="gzip+base64" data-uncompressed-bytes="${raw.byteLength}" data-compressed-bytes="${compressed.byteLength}">${compressed.toString('base64')}</script>`
  const path = join(directory, 'index.html')
  writeFileSync(path, bundle.replace(marker, embedded))
  await page.addInitScript(() => {
    const stages: string[] = []
    ;(window as any).__startupStages = stages
    const observer = new MutationObserver(() => {
      const stage = document.getElementById('report-startup-stage')?.textContent
      if (stage && stages.at(-1) !== stage) stages.push(stage)
      if (!stage && stages.length) observer.disconnect()
    })
    observer.observe(document, { childList: true, characterData: true, subtree: true })
  })
  try {
    await page.goto(pathToFileURL(path).href)
    await expect(page.getByRole('heading', { name: 'NVDebug Collection Report' })).toBeVisible()
    await expect(page.locator('#report-startup')).toHaveCount(0)
    expect(await page.evaluate(() => (window as any).__startupStages)).toEqual(expect.arrayContaining([
      'Decoding embedded report…', 'Decompressing report data…', 'Preparing report data…',
      'Checking report data…', 'Preparing report view…',
    ]))
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('replaces loading with an error view when the manifest cannot be read', async ({ page }) => {
  await page.route('**/manifest.json', route => route.fulfill({ status: 500, body: '' }))
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Dashboard unavailable' })).toBeVisible()
  await expect(page.locator('#report-startup')).toHaveCount(0)
})
