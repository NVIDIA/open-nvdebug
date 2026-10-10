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

import { test, expect, waitForAppReady } from './e2e-fixture'

test.describe('Navigation', () => {
  test('hash routing works', async ({ page }) => {
    await page.goto('/#/timing')
    await expect(page.getByRole('heading', { name: 'Timing Analysis' })).toBeVisible()
  })

  test('breadcrumbs show correct path', async ({ page }) => {
    await page.goto('/#/dut/DUT_1')
    const breadcrumbs = page.getByLabel('Breadcrumb')
    await expect(breadcrumbs.getByRole('link', { name: 'Home' })).toBeVisible()
    await expect(breadcrumbs.getByText('DUT_1', { exact: true })).toBeVisible()
  })

  test('file map view loads', async ({ page }) => {
    await page.goto('/#/file-map')
    await expect(page.getByRole('heading', { name: 'File Map' })).toBeVisible()
    await expect(page.locator('text=Total Files')).toBeVisible()
  })

  test('errors view shows error table', async ({ page }) => {
    await page.goto('/#/errors')
    await expect(page.locator('.ea-cluster__msg').filter({ hasText: 'Redfish resource' })).toBeVisible()
  })

  test('timing view shows charts section', async ({ page }) => {
    await page.goto('/#/timing')
    await expect(page.getByRole('heading', { name: 'Timing Analysis' })).toBeVisible()
  })

  test('heatmap view loads', async ({ page }) => {
    await page.goto('/#/heatmap')
    await expect(page.getByRole('heading', { name: 'Health Heatmap' })).toBeVisible()
  })

  test('theme toggle works', async ({ page }) => {
    await page.goto('/')
    await waitForAppReady(page)
    const html = page.locator('html')
    const initialTheme = await html.getAttribute('data-theme')
    // Press 't' to toggle
    await page.keyboard.press('t')
    const newTheme = await html.getAttribute('data-theme')
    expect(newTheme).not.toBe(initialTheme)
  })
})
