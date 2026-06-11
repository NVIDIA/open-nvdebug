import { test, expect } from '@playwright/test'

test.describe('Keyboard Shortcuts', () => {
  test('? opens shortcut help', async ({ page }) => {
    await page.goto('/')
    await page.keyboard.press('?')
    await expect(page.locator('text=Keyboard Shortcuts')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.locator('text=Keyboard Shortcuts')).not.toBeVisible()
  })

  test('Ctrl+K opens command palette', async ({ page }) => {
    await page.goto('/')
    await page.keyboard.press('Control+k')
    await expect(page.locator('text=commands')).toBeVisible({ timeout: 3000 })
  })
})
