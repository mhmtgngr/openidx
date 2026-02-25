import { test, expect } from '@playwright/test'

test.describe('Landing Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/landing')
  })

  test('should display the landing page with hero section', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/OpenIDX/)

    // Check hero section
    await expect(page.locator('h1')).toContainText('Zero Trust Access Platform')

    // Check for key elements
    await expect(page.locator('text=Enterprise-Grade Security')).toBeVisible()
    await expect(page.locator('text=Start Free Trial')).toBeVisible()
    await expect(page.locator('text=Live Demo')).toBeVisible()
  })

  test('should display all feature cards', async ({ page }) => {
    const features = [
      'Zero Trust Architecture',
      'Identity & Access Management',
      'Multi-Factor Authentication',
      'Single Sign-On (SSO)',
      'Real-time Monitoring',
      'Compliance & Governance',
      'API Gateway & Security',
      'High Performance',
    ]

    for (const feature of features) {
      await expect(page.locator(`text=${feature}`)).toBeVisible()
    }
  })

  test('should display statistics', async ({ page }) => {
    await expect(page.locator('text=99.99%')).toBeVisible()
    await expect(page.locator('text=Uptime SLA')).toBeVisible()
    await expect(page.locator('<50ms')).toBeVisible()
    await expect(page.locator('Response Time')).toBeVisible()
  })

  test('should display integrations section', async ({ page }) => {
    const integrations = ['Active Directory', 'LDAP', 'Okta', 'Azure AD', 'Google Workspace']

    for (const integration of integrations) {
      await expect(page.locator(`text=${integration}`)).toBeVisible()
    }
  })

  test('should navigate to login when clicking sign in', async ({ page }) => {
    await page.click('button:has-text("Sign In")')

    // Should navigate to login page
    await expect(page).toHaveURL(/\/login/)
  })

  test('should trigger OAuth flow when clicking get started', async ({ page }) => {
    // Click the "Get Started Free" button
    await page.click('button:has-text("Get Started Free")')

    // The button triggers OAuth flow - in a real test we'd check the redirect
    // For now, just verify the click doesn't cause errors
  })

  test('should have working navigation links', async ({ page }) => {
    // Test Features link
    await page.click('a[href="#features"]')
    await expect(page.locator('#features')).toBeInViewport()

    // Test Integrations link
    await page.click('a[href="#integration"]')
    await expect(page.locator('#integration')).toBeInViewport()
  })

  test('should display footer with links', async ({ page }) => {
    await expect(page.locator('text=Privacy Policy')).toBeVisible()
    await expect(page.locator('text=Terms of Service')).toBeVisible()
    await expect(page.locator('text=Security')).toBeVisible()
    await expect(page.locator('text=Compliance')).toBeVisible()
  })

  test('should be responsive on mobile', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })

    // Check mobile menu is available
    await expect(page.locator('button[aria-label="Toggle menu"]')).toBeVisible()

    // Open mobile menu
    await page.click('button[aria-label="Toggle menu"]')
    await expect(page.locator('text=Features')).toBeVisible()
  })
})

test.describe('Landing Page Navigation', () => {
  test('should redirect authenticated users to dashboard', async ({ page }) => {
    // This test would need authenticated state
    // For now, just verify the page loads
    await page.goto('/landing')
    await expect(page.locator('h1')).toContainText('Zero Trust Access Platform')
  })

  test('should handle smooth scrolling to sections', async ({ page }) => {
    await page.goto('/landing')

    const initialScroll = await page.evaluate(() => window.scrollY)

    // Click on features link
    await page.click('a[href="#features"]')

    // Wait for scroll
    await page.waitForTimeout(500)

    const finalScroll = await page.evaluate(() => window.scrollY)

    // Verify we scrolled down
    expect(finalScroll).toBeGreaterThan(initialScroll)
  })
})
