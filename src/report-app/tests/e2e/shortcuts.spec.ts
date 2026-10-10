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

test.describe('Keyboard Shortcuts', () => {
  test('? opens shortcut help', async ({ page }) => {
    await page.goto('/')
    await waitForAppReady(page)
    await page.keyboard.press('?')
    await expect(page.locator('text=Keyboard Shortcuts')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.locator('text=Keyboard Shortcuts')).not.toBeVisible()
  })

  test('Ctrl+K opens command palette', async ({ page }) => {
    await page.goto('/')
    await waitForAppReady(page)
    await page.keyboard.press('Control+k')
    await expect(page.locator('text=commands')).toBeVisible({ timeout: 3000 })
  })
})
