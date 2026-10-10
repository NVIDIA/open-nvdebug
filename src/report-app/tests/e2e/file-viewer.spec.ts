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

test.describe('File Viewer', () => {
  test('file map shows all files with table view', async ({ page }) => {
    await page.goto('/#/file-map')
    await expect(page.getByRole('heading', { name: 'File Map' })).toBeVisible()
    await expect(page.locator('text=Total Files')).toBeVisible()
  })

  test('file map tree view toggle works', async ({ page }) => {
    await page.goto('/#/file-map')
    await page.getByRole('button', { name: 'Tree', exact: true }).click()
    await expect(page.locator('.nv-sidebar__link').filter({ hasText: 'DUT_1' }).first()).toBeVisible()
  })

  test('file map DUT filter works', async ({ page }) => {
    await page.goto('/#/file-map')
    const select = page.locator('select').first()
    await select.selectOption({ index: 1 })
    await page.waitForLoadState('networkidle')
  })

  test('file map export CSV works', async ({ page }) => {
    await page.goto('/#/file-map')
    const downloadPromise = page.waitForEvent('download')
    await page.locator('button:has-text("Export CSV")').click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toContain('nvdebug-files')
    expect(download.suggestedFilename()).toContain('.csv')
  })

  test('file view loads content', async ({ page }) => {
    await page.goto('/#/file-map')
    await page.locator('table tbody tr').first().click()
    await page.waitForURL(/#\/file\//)
    await expect(page.locator('.file-info-bar')).toBeVisible({ timeout: 5000 })
  })

  test('split view accessible via route', async ({ page }) => {
    await page.goto('/#/split')
    await expect(page.locator('text=Side-by-Side')).toBeVisible()
    await expect(page.locator('select')).toHaveCount(2)
  })
})
