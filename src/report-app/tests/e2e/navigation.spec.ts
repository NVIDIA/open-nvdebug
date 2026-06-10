import { test, expect } from '@playwright/test'

test.describe('Navigation', () => {
  test('hash routing works', async ({ page }) => {
    await page.goto('/#/timing')
    await expect(page.locator('h2')).toContainText(/Timing/i)
  })

  test('breadcrumbs show correct path', async ({ page }) => {
    await page.goto('/#/dut/DUT_1')
    await expect(page.locator('text=Dashboard')).toBeVisible()
    await expect(page.locator('text=DUT_1')).toBeVisible()
  })

  test('file map view loads', async ({ page }) => {
    await page.goto('/#/file-map')
    await expect(page.locator('text=File Map')).toBeVisible()
    await expect(page.locator('text=Total Files')).toBeVisible()
  })

  test('errors view shows error table', async ({ page }) => {
    await page.goto('/#/errors')
    await expect(page.locator('text=Connection timeout')).toBeVisible()
  })

  test('timing view shows charts section', async ({ page }) => {
    await page.goto('/#/timing')
    await expect(page.locator('text=Timing')).toBeVisible()
  })

  test('heatmap view loads', async ({ page }) => {
    await page.goto('/#/heatmap')
    await expect(page.locator('text=Health Heatmap')).toBeVisible()
  })

  test('theme toggle works', async ({ page }) => {
    await page.goto('/')
    const html = page.locator('html')
    const initialTheme = await html.getAttribute('data-theme')
    // Press 't' to toggle
    await page.keyboard.press('t')
    const newTheme = await html.getAttribute('data-theme')
    expect(newTheme).not.toBe(initialTheme)
  })
})
