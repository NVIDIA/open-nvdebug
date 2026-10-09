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

test.describe('Performance Budget', () => {
  test.slow()

  test('dashboard renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'NVDebug Collection Report' })).toBeVisible()
    await expect(page.getByTitle('View all DUTs')).toBeVisible()
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(5000)
  })

  test('file map renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/#/file-map')
    await expect(page.getByRole('heading', { name: 'File Map' })).toBeVisible()
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(5000)
  })

  test('timing view renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/#/timing')
    await expect(page.getByRole('heading', { name: 'Timing Analysis' })).toBeVisible()
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(6000)
  })

  test('error aggregation renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/#/errors')
    await expect(page.locator('text=Errors').first()).toBeVisible()
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(5000)
  })

  test('theme toggle is fast', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'NVDebug Collection Report' })).toBeVisible()
    const html = page.locator('html')
    const before = await html.getAttribute('data-theme')
    await page.keyboard.press('t')
    await expect(html).not.toHaveAttribute('data-theme', before ?? '')
  })
})
