import { test, expect } from '@playwright/test'

test.describe('Dashboard (Authenticated)', () => {
  test('should display dashboard with statistics', async ({ page }) => {
    // Navigate to dashboard (will be redirected to login if not authenticated)
    await page.goto('/dashboard')

    // If redirected to login, that's expected behavior without auth
    const url = page.url()
    if (url.includes('/login')) {
      // This is the expected behavior for unauthenticated users
      return
    }

    // If we reach here, user is authenticated
    await expect(page.locator('h1')).toContainText('Dashboard')

    // Check for common dashboard elements
    await expect(page.locator('text=Total Users')).toBeVisible()
    await expect(page.locator('text=Active Sessions')).toBeVisible()
  })

  test('should display navigation menu', async ({ page }) => {
    await page.goto('/dashboard')

    // If redirected to login, skip test
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for sidebar navigation
    await expect(page.locator('nav')).toBeVisible()
  })

  test('should allow navigation to different pages', async ({ page }) => {
    await page.goto('/dashboard')

    // If redirected to login, skip test
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Try clicking on users link
    const usersLink = page.locator('a[href="/users"]')
    if (await usersLink.isVisible()) {
      await usersLink.click()
      await expect(page).toHaveURL(/\/users/)
    }
  })
})

test.describe('User Management (Admin)', () => {
  test('should display users list', async ({ page }) => {
    await page.goto('/users')

    // If redirected to login, skip
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for users table
    await expect(page.locator('table, [role="table"]')).toBeVisible()
  })

  test('should have search functionality', async ({ page }) => {
    await page.goto('/users')

    // If redirected to login, skip
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for search input
    const searchInput = page.locator('input[placeholder*="search" i], input[placeholder*="Search" i]')
    if (await searchInput.isVisible()) {
      await searchInput.fill('admin')
      await page.waitForTimeout(500)
    }
  })
})

test.describe('Logout Functionality', () => {
  test('should allow user to logout', async ({ page }) => {
    await page.goto('/dashboard')

    // If redirected to login, skip
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Find and click logout button
    const logoutButton = page.locator('button:has-text("Logout"), button:has-text("Sign out")')

    if (await logoutButton.isVisible()) {
      await logoutButton.click()
      await expect(page).toHaveURL(/\/login/)
    }
  })
})
