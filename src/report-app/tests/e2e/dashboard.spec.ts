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

import { test, expect } from './e2e-fixture'
import { readFileSync } from 'node:fs'

test.describe('Dashboard', () => {
  test('renders executive summary metrics with correct data', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'NVDebug Collection Report' })).toBeVisible()
    // Executive-summary tiles should show data from manifest
    const totalDuts = page.getByTitle('View all DUTs')
    await expect(totalDuts).toBeVisible()
    await expect(totalDuts).toContainText('2')
  })

  test('shows collection status progress bar', async ({ page }) => {
    await page.goto('/')
    // Progress bar segments should reflect the fixture's status counts.
    await expect(page.locator('.nv-progress')).toBeVisible()
    await expect(page.locator('.nv-progress__segment[title="success: 8"]')).toBeVisible()
    await expect(page.locator('.nv-progress__segment[title="error: 1"]')).toBeVisible()
  })

  test('DUT table has correct rows', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('row').filter({
      has: page.getByRole('cell', { name: 'DUT_1', exact: true }),
    })).toBeVisible()
  })

  test('navigates to DUT view on row click', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('row').filter({
      has: page.getByRole('cell', { name: 'DUT_1', exact: true }),
    }).click()
    await expect(page).toHaveURL(/#\/dut\/DUT_1/)
  })

  test('shows preflight status tags and links to the full preflight report', async ({ page }) => {
    await page.goto('/')
    const row = page.getByRole('row').filter({
      has: page.getByRole('cell', { name: 'DUT_1', exact: true }),
    })
    const preflightButton = row.getByRole('button', {
      name: 'View preflight details for DUT_1: 3 passed, 1 warning',
    })

    await expect(row.getByText('Pass 3', { exact: true })).toBeVisible()
    await expect(row.getByText('Warning 1', { exact: true })).toBeVisible()

    await preflightButton.click()
    await expect(page).toHaveURL(/#\/$/)
    const dialog = page.locator('.nv-modal')
    await expect(dialog.getByRole('heading', { name: 'Preflight Checks — DUT_1' })).toBeVisible()
    await expect(dialog.getByRole('cell', { name: 'SSH Connectivity' })).toBeVisible()

    await dialog.getByRole('link', { name: 'View Full Preflight Report' }).click()
    await expect(page).toHaveURL(/#\/dut\/DUT_1\/preflight/)
    await expect(page.getByRole('heading', { name: 'Preflight Checks — DUT_1' })).toBeVisible()
    await expect(page.getByRole('cell', { name: 'SSH Connectivity' })).toBeVisible()
  })

  test('status metric tile navigates to status page', async ({ page }) => {
    await page.goto('/')
    await page.getByTitle('View failed collectors').click()
    await expect(page).toHaveURL(/#\/status\/error/)
  })

  test('prioritizes charts, pairs configuration with anomalies, and bounds runtime logs', async ({ page }) => {
    const fixture = JSON.parse(readFileSync('tests/fixtures/sample_manifest.json', 'utf8'))
    for (const group of fixture.duts[0].collector_groups) {
      for (const collector of group.collectors) collector.status = 'error'
    }
    fixture.file_index.push(...Array.from({ length: 40 }, (_, index) => ({
      path: `DUT_${index + 100}/nvdebug_runtime_output.txt`, size: 10, type: 'text',
      collector_id: '', dut_id: `DUT_${index + 100}`, viewer_hint: 'log-viewer',
    })))
    await page.route('**/manifest.json', route => route.fulfill({ json: fixture }))
    await page.setViewportSize({ width: 1440, height: 1100 })
    await page.goto('/')
    const charts = page.locator('.charts-section')
    const tools = page.locator('.dashboard-quick-actions')
    const details = page.locator('.dashboard-details')
    await expect(details.getByRole('heading', { name: /Anomalies Detected/ })).toBeVisible()
    const chartsBox = (await charts.boundingBox())!
    const toolsBox = (await tools.boundingBox())!
    expect(chartsBox.y + chartsBox.height).toBeLessThan(toolsBox.y)
    const cards = details.locator(':scope > div')
    const configurationBox = (await cards.nth(0).boundingBox())!
    const anomalyBox = (await cards.nth(1).boundingBox())!
    expect(configurationBox.y).toBeCloseTo(anomalyBox.y, 0)
    expect(configurationBox.x + configurationBox.width).toBeLessThan(anomalyBox.x)

    const logs = page.locator('.qa-runtime-logs')
    expect(await logs.getAttribute('open')).toBeNull()
    expect((await logs.boundingBox())!.height).toBeLessThan(60)
    await logs.locator('summary').focus()
    await page.keyboard.press('Enter')
    await expect(logs).toHaveAttribute('open', '')
    const logGroups = logs.locator('.qa-runtime-logs__groups')
    expect((await logGroups.boundingBox())!.height).toBeLessThanOrEqual(241)
    expect(await logGroups.evaluate(element => element.scrollHeight > element.clientHeight)).toBe(true)
    await expect(logs.getByRole('link', { name: 'Runtime Output Log' }).first()).toHaveAttribute('href', /#\/file\//)

    await page.setViewportSize({ width: 390, height: 844 })
    const mobileConfiguration = (await cards.nth(0).boundingBox())!
    const mobileAnomalies = (await cards.nth(1).boundingBox())!
    expect(mobileAnomalies.y).toBeGreaterThan(mobileConfiguration.y + mobileConfiguration.height)
    expect(await tools.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true)
    expect(await details.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true)
  })

  test('preserves the collector table sort after opening details and going back', async ({ page }) => {
    await page.goto('/#/status/all')
    const timeHeader = page.getByRole('columnheader', { name: /Exec Time/ })
    await timeHeader.click()
    await timeHeader.click()
    await expect(timeHeader).toHaveAttribute('aria-sort', 'descending')
    const firstRow = page.locator('tbody tr').first()
    const sortedFirstRow = await firstRow.innerText()
    await firstRow.getByRole('button', { name: /View details/ }).click()
    await expect(page).toHaveURL(/#\/dut\//)
    await page.goBack()
    await expect(timeHeader).toHaveAttribute('aria-sort', 'descending')
    await expect(page.locator('tbody tr').first()).toHaveText(sortedFirstRow.replace(/\s+/g, ' '), { useInnerText: true })
  })

  test('explains a missing system value with its source collector outcome', async ({ page }) => {
    const fixture = JSON.parse(readFileSync('tests/fixtures/sample_manifest.json', 'utf8'))
    const source = fixture.duts[0].collector_groups[0].collectors[0]
    source.report_role = 'host_system_snapshot'
    source.status = 'skipped'
    source.reason = 'Host preflight failed: SSH authentication failed'
    fixture.duts[0].system_info.system_view = { host: { os: null }, bmc: { version: 'synthetic-bmc-version' } }
    await page.route('**/manifest.json', route => route.fulfill({ json: fixture }))
    await page.goto('/')
    await page.getByRole('row').filter({
      has: page.getByRole('cell', { name: 'DUT_1', exact: true }),
    }).getByRole('button', { name: 'View', exact: true }).click()
    const modal = page.locator('.nv-modal')
    await expect(modal).toContainText('skipped — Host preflight failed: SSH authentication failed')
    await expect(modal).toContainText('synthetic-bmc-version')
    await expect(modal.getByRole('link', { name: 'View preflight checks for this DUT' })).toBeVisible()
  })
})
