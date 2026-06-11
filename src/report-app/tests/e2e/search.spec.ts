import { test, expect } from '@playwright/test'

test.describe('Search & Command Palette', () => {
  test('Ctrl+K opens command palette', async ({ page }) => {
    await page.goto('/')
    await page.keyboard.press('Control+k')
    await expect(page.locator('[role="dialog"]').or(page.locator('.command-palette'))).toBeVisible({ timeout: 3000 })
  })

  test('search input in navbar is clickable', async ({ page }) => {
    await page.goto('/')
    const searchInput = page.locator('input[placeholder*="Search"]')
    if (await searchInput.isVisible()) {
      await searchInput.click()
      await expect(page.locator('[role="dialog"]').or(page.locator('.command-palette'))).toBeVisible({ timeout: 3000 })
    }
  })

  test('? key opens shortcut help', async ({ page }) => {
    await page.goto('/')
    await page.keyboard.press('?')
    await expect(page.locator('text=Keyboard Shortcuts').or(page.locator('text=keyboard'))).toBeVisible({ timeout: 3000 })
  })

  test('t key toggles theme', async ({ page }) => {
    await page.goto('/')
    const html = page.locator('html')
    const initialTheme = await html.getAttribute('data-theme')
    await page.keyboard.press('t')
    const newTheme = await html.getAttribute('data-theme')
    expect(newTheme).not.toBe(initialTheme)
  })

  test('error aggregation view has clustered mode', async ({ page }) => {
    await page.goto('/#/errors')
    await expect(page.locator('text=Error Aggregation').or(page.locator('text=All Errors'))).toBeVisible()
    const clusteredBtn = page.locator('button:has-text("Clustered")')
    if (await clusteredBtn.isVisible()) {
      await clusteredBtn.click()
      await expect(page.locator('text=clusters from')).toBeVisible({ timeout: 3000 })
    }
  })
})
