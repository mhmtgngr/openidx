import { test as setup, expect } from '@playwright/test'

const authFile = 'e2e/.auth/user.json'

setup('authenticate as admin', async ({ page, context }) => {
  // Navigate to login page
  await page.goto('/login')

  // Fill in login credentials (for test environment)
  // These should be configured via environment variables in CI/CD
  const username = process.env.TEST_ADMIN_USERNAME || 'admin'
  const password = process.env.TEST_ADMIN_PASSWORD || 'admin123'

  // Wait for login form to be ready
  await page.waitForSelector('input[id="username"]', { timeout: 5000 })

  // Fill login form
  await page.fill('input[id="username"]', username)
  await page.fill('input[id="password"]', password)

  // Submit login
  await page.click('button[type="submit"]')

  // Wait for successful authentication - redirect to dashboard
  await page.waitForURL(/\/dashboard/, { timeout: 15000 })

  // Wait for dashboard to load
  await expect(page.locator('h1')).toContainText('Dashboard')

  // Save authentication state
  await context.storageState({ path: authFile })
})
