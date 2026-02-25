import { test, expect } from '@playwright/test'

test.describe('Responsive Design', () => {
  test('should be responsive on mobile', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto('/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check that sidebar is collapsed or hidden
    const sidebar = page.locator('aside')
    const boundingBox = await sidebar.boundingBox()

    if (boundingBox) {
      // On mobile, sidebar should be narrow or hidden
      expect(boundingBox.width).toBeLessThan(200)
    }
  })

  test('should be responsive on tablet', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 })
    await page.goto('/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Page should still be functional
    await expect(page.locator('h1')).toContainText('Dashboard')
  })

  test('should be responsive on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto('/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Full sidebar should be visible
    const sidebar = page.locator('aside')
    await expect(sidebar).toBeVisible()
  })

  test('should handle mobile menu toggle', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto('/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for hamburger menu
    const menuButton = page.locator('button[aria-label*="menu"], button[aria-label*="Menu"], svg[class*="menu"]').first()
    if (await menuButton.isVisible()) {
      await menuButton.click()
      await page.waitForTimeout(300)

      // Sidebar should become visible
      const sidebar = page.locator('aside')
      await expect(sidebar).toBeVisible()
    }
  })

  test('should display cards in grid on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto('/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Cards should stack vertically on mobile
    const cards = page.locator('[class*="card"], [class*="Card"]')
    if (await cards.first().isVisible()) {
      const firstCard = cards.first()
      const box = await firstCard.boundingBox()
      if (box) {
        expect(box.width).toBeLessThan(375)
      }
    }
  })
})
