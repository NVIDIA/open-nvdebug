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

test.describe('Search & Command Palette', () => {
  test('Ctrl+K opens command palette', async ({ page }) => {
    await page.goto('/')
    await waitForAppReady(page)
    await page.keyboard.press('Control+k')
    await expect(page.locator('.nv-command-overlay')).toBeVisible({ timeout: 3000 })
  })

  test('search input in navbar is clickable', async ({ page }) => {
    await page.goto('/')
    const searchInput = page.locator('input[placeholder*="Search"]')
    if (await searchInput.isVisible()) {
      await searchInput.click()
      await expect(page.locator('.nv-command-overlay')).toBeVisible({ timeout: 3000 })
    }
  })

  test('? key opens shortcut help', async ({ page }) => {
    await page.goto('/')
    await waitForAppReady(page)
    await page.keyboard.press('?')
    await expect(page.locator('text=Keyboard Shortcuts').or(page.locator('text=keyboard'))).toBeVisible({ timeout: 3000 })
  })

  test('t key toggles theme', async ({ page }) => {
    await page.goto('/')
    await waitForAppReady(page)
    const html = page.locator('html')
    const initialTheme = await html.getAttribute('data-theme')
    await page.keyboard.press('t')
    const newTheme = await html.getAttribute('data-theme')
    expect(newTheme).not.toBe(initialTheme)
  })

  test('error aggregation view has clustered mode', async ({ page }) => {
    await page.goto('/#/errors')
    await expect(page.getByRole('heading', { name: 'All Errors (2)' })).toBeVisible()
    await page.getByRole('button', { name: 'Clustered', exact: true }).click()
    await expect(page.getByText(/clusters from 2 errors/)).toBeVisible({ timeout: 3000 })
  })
})
