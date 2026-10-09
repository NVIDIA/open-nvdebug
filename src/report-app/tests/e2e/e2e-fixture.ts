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

import { test as base, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { readFileSync } from 'node:fs'

const manifest = JSON.parse(
  readFileSync(new URL('../fixtures/sample_manifest.json', import.meta.url), 'utf8'),
)

export const test = base.extend({
  page: async ({ page }, use) => {
    await page.addInitScript((fixtureManifest) => {
      window.__MANIFEST__ = fixtureManifest
      localStorage.setItem('nv-tour-completed', 'true')
    }, manifest)
    await page.route(/\/DUT_[^/]+\//, async (route) => {
      const pathname = new URL(route.request().url()).pathname
      if (pathname.endsWith('.json')) {
        await route.fulfill({
          contentType: 'application/json',
          body: JSON.stringify({ '@odata.id': pathname, fixture: true }),
        })
      } else {
        await route.fulfill({
          contentType: 'text/plain',
          body: `fixture content for ${pathname}`,
        })
      }
    })
    await use(page)
  },
})

export async function waitForAppReady(page: Page): Promise<void> {
  await expect(page.locator('#app[data-theme]')).toBeVisible()
}

export { expect }
