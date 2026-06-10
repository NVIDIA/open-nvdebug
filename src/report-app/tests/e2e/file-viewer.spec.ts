import { test, expect } from '@playwright/test'

test.describe('File Viewer', () => {
  test('file map shows all files with table view', async ({ page }) => {
    await page.goto('/#/file-map')
    await expect(page.locator('text=File Map')).toBeVisible()
    await expect(page.locator('text=Total Files')).toBeVisible()
  })

  test('file map tree view toggle works', async ({ page }) => {
    await page.goto('/#/file-map')
    await page.locator('button:has-text("Tree")').click()
    await expect(page.locator('.file-tree')).toBeVisible({ timeout: 5000 })
  })

  test('file map DUT filter works', async ({ page }) => {
    await page.goto('/#/file-map')
    const select = page.locator('select').first()
    await select.selectOption({ index: 1 })
    await page.waitForLoadState('networkidle')
  })

  test('file map export CSV works', async ({ page }) => {
    await page.goto('/#/file-map')
    const downloadPromise = page.waitForEvent('download')
    await page.locator('button:has-text("Export CSV")').click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toContain('nvdebug-files')
    expect(download.suggestedFilename()).toContain('.csv')
  })

  test('file view loads content', async ({ page }) => {
    await page.goto('/#/file-map')
    await page.locator('table tbody tr').first().click()
    await page.waitForURL(/#\/file\//)
    await expect(page.locator('.file-info-bar')).toBeVisible({ timeout: 5000 })
  })

  test('split view accessible via route', async ({ page }) => {
    await page.goto('/#/split')
    await expect(page.locator('text=Side-by-Side')).toBeVisible()
    await expect(page.locator('select')).toHaveCount(2)
  })
})
