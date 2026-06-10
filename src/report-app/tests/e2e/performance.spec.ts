import { test, expect } from '@playwright/test'

test.describe('Performance Budget', () => {
  test.slow()

  test('dashboard renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/')
    await expect(page.locator('text=NVDebug')).toBeVisible()
    await expect(page.locator('text=Total DUTs')).toBeVisible()
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(5000)
  })

  test('file map renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/#/file-map')
    await expect(page.locator('text=File Map')).toBeVisible()
    const elapsed = Date.now() - start
    expect(elapsed).toBeLessThan(5000)
  })

  test('timing view renders within budget', async ({ page }) => {
    const start = Date.now()
    await page.goto('/#/timing')
    await expect(page.locator('text=Timing Analysis')).toBeVisible()
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
    await expect(page.locator('text=NVDebug')).toBeVisible()
    const html = page.locator('html')
    const before = await html.getAttribute('data-theme')
    await page.keyboard.press('t')
    await expect(html).not.toHaveAttribute('data-theme', before ?? '')
  })
})
