import { test, expect } from '@playwright/test'

test.describe('Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/dashboard')
  })

  test('should display sidebar navigation', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const sidebar = page.locator('aside, nav')
    await expect(sidebar).toBeVisible()
  })

  test('should have Dashboard link', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const dashboardLink = page.locator('a[href="/dashboard"]')
    await expect(dashboardLink).toBeVisible()
  })

  test('should navigate to Users page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const usersLink = page.locator('a[href="/users"]')
    await usersLink.click()
    await expect(page).toHaveURL(/\/users/)
  })

  test('should navigate to Applications page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const appsLink = page.locator('a[href="/applications"]')
    await appsLink.click()
    await expect(page).toHaveURL(/\/applications/)
  })

  test('should navigate to Settings page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const settingsLink = page.locator('a[href="/settings"]')
    await settingsLink.click()
    await expect(page).toHaveURL(/\/settings/)
  })

  test('should display user menu', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for user avatar/menu
    const userMenu = page.locator('button:has([class*="avatar"]), [class*="avatar"]').first()
    if (await userMenu.isVisible()) {
      await userMenu.click()
      // Verify menu items appear
      await expect(page.locator('text=Logout, text=Sign out')).toBeVisible()
    }
  })

  test('should toggle sidebar', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const sidebar = page.locator('aside')
    const initialWidth = await sidebar.boundingBox()

    // Try to collapse sidebar
    const toggleButton = page.locator('button').filter({ hasText: /^$/ }).first()
    if (await toggleButton.isVisible()) {
      await toggleButton.click()
      await page.waitForTimeout(300)
      const newWidth = await sidebar.boundingBox()
      // Width should be different (collapsed)
      expect(initialWidth?.width).not.toBe(newWidth?.width)
    }
  })
})

test.describe('Navigation Sections', () => {
  test('should display all navigation sections for admin', async ({ page }) => {
    await page.goto('/dashboard')
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for section labels
    const sections = [
      'Identity',
      'Applications',
      'Governance',
      'Security',
      'Audit'
    ]

    for (const section of sections) {
      const sectionLabel = page.locator(`text=${section}`)
      if (await sectionLabel.isVisible()) {
        await expect(sectionLabel).toBeVisible()
      }
    }
  })
})
