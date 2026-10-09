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

const fixture = JSON.parse(readFileSync('tests/fixtures/sample_manifest.json', 'utf8'))
fixture.duts[0].collector_groups[0].collectors[0].id = 'R1'
fixture.duts[0].collector_groups[0].collectors[1].id = 'R2'
fixture.duts[1].collector_groups[0].collectors[0].id = 'R1'
fixture.file_index.push(...['DUT_1', 'DUT_2'].map(dut => ({
  path: `${dut}/nvdebug_runtime_output.txt`, dut_id: dut, collector_id: '', size: 600, type: 'log',
})))

const log = [
  '[time] [INFO] [CID:R10] [redfish] another collector',
  '[time] [INFO] [CID:R2] [redfish] R2 context mentions [CID:R1]',
  '2026-09-17 10:00:00.001 - CID:R1] [redfish - INFO - request started',
  '[time] [ERROR] [CID:R1] [redfish] request failed',
  'Traceback:',
  '  synthetic exception detail',
  '[time] [INFO] [runner] unrelated lifecycle event',
].join('\n')

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('nv-tour-completed', 'true'))
  await page.route('**/manifest.json', route => route.fulfill({ json: fixture }))
})

test('shows scoped runtime logs, filters and exports them, and switches collector and node in place', async ({ page }) => {
  const requests: string[] = []
  await page.route('**/nvdebug_runtime_output.txt', route => {
    requests.push(route.request().url())
    return route.fulfill({ contentType: 'text/plain', body: route.request().url().includes('DUT_2')
      ? '[time] [INFO] [CID:R1] [redfish] second node only' : log })
  })
  await page.goto('/#/dut/DUT_1/redfish/R1')
  const panel = page.getByRole('region', { name: 'Runtime Logs' })
  const content = panel.locator('.nv-log__content')
  await expect(content).toContainText('request failed')
  await expect(content).toContainText('synthetic exception detail')
  await expect(content).not.toContainText('another collector')
  await expect(content).not.toContainText('R2 context')
  await expect(content).not.toContainText('unrelated lifecycle')
  expect((await content.boundingBox())!.height).toBeLessThanOrEqual(361)
  await panel.getByRole('combobox', { name: 'Log level' }).selectOption('ERROR')
  await expect(content).toContainText('request failed')
  await expect(content).not.toContainText('request started')
  const downloadPromise = page.waitForEvent('download')
  await panel.getByRole('button', { name: 'Download', exact: true }).click()
  const download = await downloadPromise
  expect(readFileSync((await download.path())!, 'utf8')).toContain('[CID:R1] [redfish] request failed')
  await expect(panel.getByRole('link', { name: 'Open full node log' }))
    .toHaveAttribute('href', '#/file/DUT_1%2Fnvdebug_runtime_output.txt')

  await page.locator('.nv-sidebar').getByRole('link', { name: /R2 —/ }).click()
  await expect(content).toContainText('R2 context')
  await expect(content).not.toContainText('request failed')
  await page.evaluate(() => { window.location.hash = '/dut/DUT_2/redfish/R1' })
  await expect(content).toContainText('second node only')
  await expect(content).not.toContainText('request started')
  expect(requests.some(url => url.includes('DUT_1/'))).toBe(true)
  expect(requests.some(url => url.includes('DUT_2/'))).toBe(true)
})

test('shows a recoverable inline error when the runtime log cannot be read', async ({ page }) => {
  let reads = 0
  await page.route('**/DUT_1/nvdebug_runtime_output.txt', route => {
    reads += 1
    return route.fulfill({ status: reads === 1 ? 404 : 200, contentType: 'text/plain', body: log })
  })
  await page.goto('/#/dut/DUT_1/redfish/R1')
  const panel = page.getByRole('region', { name: 'Runtime Logs' })
  await expect(panel.getByRole('alert')).toContainText('HTTP 404')
  await panel.getByRole('button', { name: 'Retry runtime logs' }).click()
  await expect(panel.locator('.nv-log__content')).toContainText('request failed')
  await expect(page).toHaveURL(/#\/dut\/DUT_1\/redfish\/R1$/)
})

test('opens offline collector logs after selecting the report folder on the collector page', async ({ page }) => {
  const directory = mkdtempSync(join(tmpdir(), 'nvdebug-collector-logs-e2e-'))
  mkdirSync(join(directory, 'reports'))
  mkdirSync(join(directory, 'DUT_1'))
  const reportPath = join(directory, 'reports', 'index.html')
  const embedded = `<script>window.__MANIFEST__=${JSON.stringify(fixture).replace(/</g, '\\u003c')}</script>`
  writeFileSync(reportPath, readFileSync('dist/index.html', 'utf8').replace('<!-- __NVDEBUG_MANIFEST_PLACEHOLDER__ -->', embedded))
  writeFileSync(join(directory, 'DUT_1', 'nvdebug_runtime_output.txt'), log)
  try {
    await page.goto(`${pathToFileURL(reportPath).href}#/dut/DUT_1/redfish/R1`)
    const panel = page.getByRole('region', { name: 'Runtime Logs' })
    await expect(panel).toContainText('Select the report folder')
    await panel.locator('input[webkitdirectory]').setInputFiles(directory)
    await expect(panel.locator('.nv-log__content')).toContainText('request failed')
    await expect(panel.locator('.nv-log__content')).not.toContainText('R2 context')
    await expect(page).toHaveURL(/#\/dut\/DUT_1\/redfish\/R1$/)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
