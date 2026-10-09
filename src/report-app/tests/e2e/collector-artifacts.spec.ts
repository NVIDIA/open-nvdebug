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
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { pathToFileURL } from 'node:url'
import { createServer, type Server } from 'node:http'

const fixture = JSON.parse(readFileSync('tests/fixtures/sample_manifest.json', 'utf8'))
const collector = fixture.duts[0].collector_groups[0].collectors[0]
collector.id = 'R1'
collector.files = [
  { path: 'DUT_1/redfish/events.json', size: 24, type: 'json', collector_id: 'R1',
    measurement: 'redfish_request', measurement_quality: 'measured',
    measurement_scope: 'shared_requests', shared_request_operation_count: 2, duration_seconds: null },
  { path: 'DUT_1/redfish/artifact #1?.bin', size: 3, type: 'binary', collector_id: 'R1' },
  { path: 'DUT_1/redfish/diagnostic_requests_R1.json', size: 10, type: 'json', collector_id: 'R1' },
]
collector.timing = {
  collector_started_at: collector.start_time,
  collector_ended_at: collector.end_time,
  wall_clock_duration_seconds: 5.2,
  wall_clock_is_authoritative: true,
  cumulative_operation_time_seconds: 4,
  operation_aggregation: 'top_level_contributing_spans',
  nested_operation_time_excluded_seconds: 0,
  active_operation_union_seconds: 4,
  overlapped_operation_time_seconds: 0,
  unattributed_wall_time_seconds: 1.2,
  operation_sum_equals_wall_clock: false,
  artifact_timings: [],
  operations: Array.from({ length: 40 }, (_, index) => ({
    operation_id: `request-${index}`, parent_id: null, operation_type: 'request',
    name: `Inventory request ${index}`, stage: 'execution', hook: null,
    started_at: null, ended_at: null, duration_seconds: 0.1, status: 'success',
    artifact_paths: [], size_bytes: null, contributes_to_active_time: true, metadata: {},
  })),
}
const skipped = fixture.duts[0].collector_groups[0].collectors[1]
skipped.id = 'R2'
skipped.status = 'skipped'
skipped.reason = 'Preflight failed: synthetic host authentication failure.'
skipped.files = [{ ...collector.files[2], collector_id: 'R2' }]
skipped.stage_timing = { validation: null, discovery: null, execution: null, post_processing: null }
fixture.file_index.push(...collector.files.map((file: object) => ({ ...file, dut_id: 'DUT_1' })))
fixture.file_index.push({ path: 'DUT_1/nvdebug_runtime_output.txt', size: 100, type: 'log', dut_id: 'DUT_1', collector_id: '' })
const runtimeLog = '[time] [INFO] [CID:R1] [redfish] synthetic request completed'
const binary = Buffer.from([0, 255, 128])
let server: Server
let reportUrl: string

test.beforeAll(async () => {
  const bundle = readFileSync('dist/index.html')
  server = createServer((request, response) => {
    const path = decodeURIComponent(new URL(request.url || '/', 'http://localhost').pathname)
    if (path === '/reports/' || path === '/reports/index.html') {
      response.writeHead(200, { 'Content-Type': 'text/html' }).end(bundle)
    } else if (path === '/reports/manifest.json') {
      response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(fixture))
    } else if (path === '/DUT_1/redfish/artifact #1?.bin') {
      // Serve real bytes: Chromium's native downloads bypass page.route mocks.
      response.writeHead(200, { 'Content-Type': 'application/octet-stream' }).end(binary)
    } else if (path === '/DUT_1/redfish/events.json') {
      response.writeHead(200, { 'Content-Type': 'application/json' }).end('{"event":"synthetic"}')
    } else if (path === '/DUT_1/nvdebug_runtime_output.txt') {
      response.writeHead(200, { 'Content-Type': 'text/plain' }).end(runtimeLog)
    } else {
      response.writeHead(404).end()
    }
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Missing test server address')
  reportUrl = `http://127.0.0.1:${address.port}/reports/`
})

test.afterAll(async () => {
  server.closeAllConnections()
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
})

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('nv-tour-completed', 'true'))
})

test('shows artifact timing at a glance, opens an accessible timing dialog, and preserves file navigation', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(`${reportUrl}#/dut/DUT_1/redfish/R1`)
  const artifacts = page.getByRole('region', { name: 'Collected Artifacts' })
  const logs = page.getByRole('region', { name: 'Runtime Logs', exact: true })
  await expect(logs).toContainText('synthetic request completed')
  await expect(artifacts.getByRole('heading')).toHaveText('Collected Artifacts 2')
  await expect(page.locator('.cd-summary')).toContainText('Diagnostics1')
  expect((await artifacts.boundingBox())!.y).toBeLessThan(500)
  expect((await artifacts.boundingBox())!.y + (await artifacts.boundingBox())!.height).toBeLessThan((await logs.boundingBox())!.y)
  await expect(artifacts.getByRole('link', { name: 'Open events.json', exact: true })).toBeInViewport()
  await expect(page.locator('.cd-disclosure[open]')).toHaveCount(0)
  await expect(page.locator('.cd-stage-legend')).toContainText('Execution')
  await expect(artifacts.getByText('Shared requests (2 requests)', { exact: true })).toBeVisible()
  const fileTiming = artifacts.getByRole('button', { name: 'Timing details for events.json', exact: true })
  await fileTiming.click()
  const dialog = page.getByRole('dialog', { name: 'File timing details' })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText('redfish request', { exact: true })).toBeVisible()
  await expect(dialog.getByText('Shared requests (2 requests)', { exact: true })).toBeVisible()
  await expect(dialog).toContainText('not an individual file transfer duration')
  const close = dialog.getByRole('button', { name: 'Close file timing details' })
  await expect(close).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(dialog.getByRole('button', { name: /View operation timing/ })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(close).toBeFocused()
  await page.keyboard.press('Shift+Tab')
  await expect(dialog.getByRole('button', { name: /View operation timing/ })).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(close).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(fileTiming).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: /View operation timing/ }).click()
  const timing = page.getByRole('region', { name: 'Operation Timing' })
  await expect(dialog).toBeHidden()
  await expect(timing).toBeFocused()
  await expect(timing.getByRole('heading')).toBeInViewport()
  await page.getByRole('navigation', { name: 'Collector sections' }).getByRole('button', { name: 'Artifacts', exact: true }).click()

  const downloadPromise = page.waitForEvent('download')
  await artifacts.getByRole('link', { name: 'Download artifact #1?.bin', exact: true }).click()
  const download = await downloadPromise
  // Chromium replaces filename characters that are unsafe on some filesystems.
  expect(download.suggestedFilename()).toBe('artifact #1_.bin')
  expect(readFileSync((await download.path())!).length).toBe(binary.length)
  expect(readFileSync((await download.path())!)).toEqual(binary)

  const sizeHeading = artifacts.getByRole('columnheader', { name: 'Size' })
  await sizeHeading.press('Enter')
  await expect(sizeHeading).toHaveAttribute('aria-sort', 'ascending')
  await artifacts.getByRole('link', { name: 'Open events.json', exact: true }).click()
  await expect(page).toHaveURL(/#\/file\/DUT_1%2Fredfish%2Fevents.json$/)
  await page.goBack()
  await expect(sizeHeading).toHaveAttribute('aria-sort', 'ascending')

  const navigation = page.getByRole('navigation', { name: 'Collector sections' })
  await navigation.getByRole('button', { name: 'Timing', exact: true }).click()
  await expect(timing).toBeFocused()
  expect((await navigation.boundingBox())!.y).toBeGreaterThanOrEqual(51)
  await expect(timing.locator('tbody tr')).toHaveCount(25)
  expect((await timing.locator('.dt-scroll').boundingBox())!.height).toBeLessThanOrEqual(421)
  await navigation.getByRole('button', { name: 'Artifacts', exact: true }).click()
  await expect(artifacts).toBeFocused()
  await expect(artifacts.getByRole('heading')).toBeInViewport()
  await expect(page).toHaveURL(/#\/dut\/DUT_1\/redfish\/R1$/)

  await page.locator('.nv-sidebar').getByRole('link', { name: /R2 —/ }).click()
  await expect(page.locator('.cd-disclosure[open]')).toHaveCount(0)
  await expect(artifacts.getByRole('heading')).toHaveText('Collected Artifacts 0')
  await expect(artifacts).toContainText('This collector was skipped')
  await expect(artifacts).toContainText('1 diagnostic file is available')
  await expect(page.locator('.cd-reason')).toContainText('synthetic host authentication failure')
})

test('keeps the summary, artifacts, and section navigation usable on a narrow screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`${reportUrl}#/dut/DUT_1/redfish/R1`)
  const artifacts = page.getByRole('region', { name: 'Collected Artifacts' })
  await expect(artifacts.getByRole('heading')).toBeInViewport()
  expect((await artifacts.boundingBox())!.x).toBeLessThan(20)
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
  await artifacts.getByRole('button', { name: 'Timing details for events.json', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'File timing details' })
  await expect(dialog.getByText('redfish request', { exact: true })).toBeVisible()
  expect((await dialog.boundingBox())!.width).toBeLessThanOrEqual(358)
  await dialog.getByRole('button', { name: 'Close file timing details' }).click()
  await expect(dialog).toBeHidden()
  const nav = page.getByRole('navigation', { name: 'Collector sections' })
  await nav.getByRole('button', { name: 'Runtime Logs', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Runtime Logs', exact: true })).toBeInViewport()
  await expect(page).toHaveURL(/#\/dut\/DUT_1\/redfish\/R1$/)
})

test('downloads original binary artifacts from a selected offline folder', async ({ page }) => {
  const directory = mkdtempSync(join(tmpdir(), 'nvdebug-collector-artifacts-e2e-'))
  mkdirSync(join(directory, 'reports'))
  mkdirSync(join(directory, 'DUT_1', 'redfish'), { recursive: true })
  const reportPath = join(directory, 'reports', 'index.html')
  const embedded = `<script>window.__MANIFEST__=${JSON.stringify(fixture).replace(/</g, '\\u003c')}</script>`
  writeFileSync(reportPath, readFileSync('dist/index.html', 'utf8').replace('<!-- __NVDEBUG_MANIFEST_PLACEHOLDER__ -->', embedded))
  writeFileSync(join(directory, 'DUT_1', 'redfish', 'artifact #1?.bin'), binary)
  writeFileSync(join(directory, 'DUT_1', 'nvdebug_runtime_output.txt'), runtimeLog)
  try {
    await page.goto(`${pathToFileURL(reportPath).href}#/dut/DUT_1/redfish/R1`)
    const artifacts = page.getByRole('region', { name: 'Collected Artifacts' })
    const button = artifacts.getByRole('button', { name: 'Download artifact #1?.bin', exact: true })
    await expect(button).toBeDisabled()
    await artifacts.locator('input[webkitdirectory]').setInputFiles(directory)
    await expect(button).toBeEnabled()
    await expect(artifacts.getByRole('button', { name: 'Download events.json', exact: true })).toBeDisabled()
    await expect(artifacts).toContainText('Missing from selected folder')
    const downloadPromise = page.waitForEvent('download')
    await button.click()
    const download = await downloadPromise
    expect(readFileSync((await download.path())!)).toEqual(binary)
    await expect(page.getByRole('region', { name: 'Runtime Logs', exact: true })).toContainText('synthetic request completed')
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
