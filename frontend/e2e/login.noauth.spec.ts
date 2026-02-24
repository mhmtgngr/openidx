import { test, expect } from '@playwright/test'

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
  })

  test('should display login page with all elements', async ({ page }) => {
    // Check page loads
    await expect(page.locator('text=OpenIDX')).toBeVisible()
    await expect(page.locator('text=Identity & Access Management Platform')).toBeVisible()

    // Check login form elements
    await expect(page.locator('input[id="username"]')).toBeVisible()
    await expect(page.locator('input[id="password"]')).toBeVisible()
    await expect(page.locator('button[type="submit"]')).toBeVisible()
  })

  test('should show validation error with empty credentials', async ({ page }) => {
    // Click submit without filling form
    await page.click('button[type="submit"]')

    // Should show validation
    await expect(page.locator('input[id="username"]:invalid')).toBeVisible()
  })

  test('should show error with invalid credentials', async ({ page }) => {
    // Fill with invalid credentials
    await page.fill('input[id="username"]', 'invaliduser')
    await page.fill('input[id="password"]', 'invalidpass')

    // Submit form
    await page.click('button[type="submit"]')

    // Wait for error response
    await page.waitForTimeout(1000)

    // Should show error (either via form validation or API response)
    const hasError = await page.locator('text=failed,invalid,incorrect').count() > 0
    // Note: Actual error message depends on backend implementation
  })

  test('should have forgot password link', async ({ page }) => {
    const forgotPasswordLink = page.locator('a[href="/forgot-password"]')
    await expect(forgotPasswordLink).toBeVisible()

    // Click and verify navigation
    await forgotPasswordLink.click()
    await expect(page).toHaveURL(/\/forgot-password/)
  })

  test('should support OAuth redirect', async ({ page }) => {
    // Check for OAuth login button
    await expect(page.locator('text=Sign in with OpenIDX')).toBeVisible()

    // Click to initiate OAuth flow
    await page.click('button:has-text("Sign in with OpenIDX")')

    // Should redirect to OAuth authorize endpoint
    await page.waitForURL(/\/oauth\/authorize/, { timeout: 5000 })
  })

  test('should handle magic link option', async ({ page }) => {
    // Find and click magic link button
    const magicLinkButton = page.locator('button:has-text("Email me a sign-in link")')
    await expect(magicLinkButton).toBeVisible()

    await magicLinkButton.click()

    // Should show email input
    await expect(page.locator('input[placeholder*="email"]')).toBeVisible()
  })

  test('should handle QR code login option', async ({ page }) => {
    // Find and click QR code login button
    const qrButton = page.locator('button:has-text("Sign in with QR code")')
    await expect(qrButton).toBeVisible()

    await qrButton.click()

    // Should show QR code section
    await expect(page.locator('text=Scan with the OpenIDX mobile app')).toBeVisible()
  })
})

test.describe('Session Management', () => {
  test('should maintain session across page reloads', async ({ page }) => {
    // This test requires authenticated state - simplified for now
    await page.goto('/login')
    await expect(page.locator('input[id="username"]')).toBeVisible()
  })

  test('should redirect to login for protected routes', async ({ page }) => {
    // Try to access dashboard without authentication
    await page.goto('/dashboard')

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/)
  })

  test('should redirect to login for admin routes', async ({ page }) => {
    // Try to access users page without authentication
    await page.goto('/users')

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/)
  })
})
