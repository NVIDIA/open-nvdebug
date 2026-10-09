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

for (const theme of ['light', 'dark']) {
  for (const view of ['dashboard', 'node']) {
    test(`prints readable ${view} content from the ${theme} theme`, async ({ page }, testInfo) => {
      await page.addInitScript(theme => localStorage.setItem('nv-theme', theme), theme)
      await page.goto(view === 'dashboard' ? '/' : '/#/dut/DUT_1')
      const heading = page.getByRole('heading', {
        name: view === 'dashboard' ? 'NVDebug Collection Report' : 'Node Report: DUT_1',
        exact: true,
      })
      await expect(heading).toBeVisible()
      const screenColor = await heading.evaluate(element => getComputedStyle(element).color)
      await page.emulateMedia({ media: 'print' })

      // Native print and Save as PDF share these styles. Check contrast against
      // plain paper, including when the user disables background graphics.
      const textContrast = await page.locator('.nv-page').evaluate(root => {
        return Array.from(root.querySelectorAll('h2, h3, h4, th, td, .nv-badge, .file-type-badge, .nv-progress__segment, .exec-summary__metric-label, .exec-summary__metric-value'))
          .filter(element => element.checkVisibility() && element.textContent?.trim())
          .map(element => {
            const color = getComputedStyle(element).color
            const channels = color.match(/[\d.]+/g)!.map(Number)
            const alpha = channels[3] ?? 1
            const [red, green, blue] = channels.slice(0, 3).map(value => {
              const channel = (value * alpha + 255 * (1 - alpha)) / 255
              return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
            })
            const luminance = 0.2126 * red + 0.7152 * green + 0.0722 * blue
            return { text: element.textContent?.trim(), color, contrast: 1.05 / (luminance + 0.05) }
          })
      })
      expect(textContrast.length).toBeGreaterThan(10)
      expect(textContrast.filter(item => item.contrast < 4.5)).toEqual([])
      await expect(page.locator('.nv-navbar')).toBeHidden()
      await expect(page.getByTitle('Print or save report as PDF')).toBeHidden()
      await expect(page.locator('.nv-page')).toHaveCSS('margin-left', '0px')
      await expect(page.locator('.dt-scroll').first()).toHaveCSS('max-height', 'none')

      if (view === 'dashboard') {
        await expect(page.locator('.exec-summary__metric')).toHaveCount(9)
        for (const metric of await page.locator('.exec-summary__metric').all()) {
          await expect(metric).toBeVisible()
          await expect(metric).toHaveCSS('background-color', 'rgb(255, 255, 255)')
        }
        await expect(page.getByRole('cell', { name: 'DUT_1', exact: true })).toBeVisible()
        await expect(page.locator('.preflight-statuses').first()).toContainText('Pass 3')
        await expect(page.locator('.preflight-statuses').first()).toBeVisible()
        await expect(page.locator('.dashboard-quick-actions')).toBeHidden()
      } else {
        await expect(page.getByRole('heading', { name: 'Execution Summary', exact: true })).toBeVisible()
        await expect(page.locator('.nv-sidebar')).toBeHidden()
        await expect(page.locator('.preflight-chip').first()).toBeVisible()
      }

      for (const printBackground of [false, true]) {
        const path = testInfo.outputPath(`report-background-${printBackground}.pdf`)
        await page.pdf({ path, preferCSSPageSize: true, printBackground })
        await testInfo.attach(`PDF with backgrounds ${printBackground ? 'enabled' : 'disabled'}`, {
          path, contentType: 'application/pdf',
        })
      }

      // Printing must not change the saved preference or the on-screen theme.
      await page.emulateMedia({ media: 'screen' })
      await expect(heading).toHaveCSS('color', screenColor)
      await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
      expect(await page.evaluate(() => localStorage.getItem('nv-theme'))).toBe(theme)
      await expect(page.getByTitle('Print or save report as PDF')).toBeVisible()
    })
  }
}
