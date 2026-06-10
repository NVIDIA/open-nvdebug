import { test, expect } from '@playwright/test'

test.describe('Dashboard', () => {
  test('renders stat cards with correct data', async ({ page }) => {
    await page.goto('/')
    await expect(page.locator('text=NVDebug')).toBeVisible()
    // Stat cards should show data from manifest
    await expect(page.locator('text=Total DUTs')).toBeVisible()
    await expect(page.locator('text=1')).toBeVisible() // 1 DUT
  })

  test('shows collection status progress bar', async ({ page }) => {
    await page.goto('/')
    // Progress bar segments should be visible
    await expect(page.locator('text=Collection Status').or(page.locator('text=66.7%'))).toBeVisible({ timeout: 5000 })
  })

  test('DUT table has correct rows', async ({ page }) => {
    await page.goto('/')
    await expect(page.locator('text=DUT_1')).toBeVisible()
  })

  test('navigates to DUT view on row click', async ({ page }) => {
    await page.goto('/')
    await page.locator('text=DUT_1').first().click()
    await expect(page).toHaveURL(/#\/dut\/DUT_1/)
  })

  test('status card navigates to status page', async ({ page }) => {
    await page.goto('/')
    // Click "Failed" stat card
    await page.locator('text=Failed').first().click()
    await expect(page).toHaveURL(/#\/status\/error/)
  })
})
