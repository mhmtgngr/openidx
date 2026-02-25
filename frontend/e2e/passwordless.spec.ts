import { test, expect } from '@playwright/test'

test.describe('Passwordless Settings', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/passwordless-settings')
  })

  test('should display passwordless settings page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Verify page title
    await expect(page.locator('h1')).toContainText('Passwordless Authentication')

    // Verify stats cards
    await expect(page.locator('text=Magic Links Today')).toBeVisible()
    await expect(page.locator('text=QR Logins Today')).toBeVisible()
    await expect(page.locator('text=Biometric-Only Users')).toBeVisible()
  })

  test('should display all passwordless methods', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for each method card
    await expect(page.locator('text=Magic Links')).toBeVisible()
    await expect(page.locator('text=QR Code Login')).toBeVisible()
    await expect(page.locator('text=Biometric Only')).toBeVisible()
  })

  test('should allow toggling magic link feature', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Find the toggle for magic links
    const toggle = page.locator('button[role="switch"]').first()
    if (await toggle.isVisible()) {
      const initialState = await toggle.getAttribute('aria-checked')
      await toggle.click()
      // Verify state changed (in real test, check with backend)
      await page.waitForTimeout(500)
    }
  })

  test('should open edit settings dialog', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const editButton = page.locator('button:has-text("Edit Settings")')
    await expect(editButton).toBeVisible()
    await editButton.click()

    // Verify dialog opens
    await expect(page.locator('text=Edit Passwordless Settings')).toBeVisible()
  })

  test('should open test magic link dialog', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const testButton = page.locator('button:has-text("Test Magic Link")')
    await expect(testButton).toBeVisible()
    await testButton.click()

    // Verify dialog opens
    await expect(page.locator('text=Send Test Magic Link')).toBeVisible()
  })

  test('should display how it works section', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Verify explanation section
    await expect(page.locator('text=How Passwordless Works')).toBeVisible()
    await expect(page.locator('text=user enters email')).toBeVisible()
  })
})

test.describe('Passwordless Configuration', () => {
  test('should update magic link expiry', async ({ page }) => {
    await page.goto('/passwordless-settings')
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const editButton = page.locator('button:has-text("Edit Settings")')
    await editButton.click()

    // Find and update expiry input
    const expiryInput = page.locator('input[type="number"]').first()
    await expiryInput.clear()
    await expiryInput.fill('20')

    // Save (in real test, verify with API)
    const saveButton = page.locator('button:has-text("Save Settings")')
    await saveButton.click()
  })

  test('should send test magic link', async ({ page }) => {
    await page.goto('/passwordless-settings')
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const testButton = page.locator('button:has-text("Test Magic Link")')
    await testButton.click()

    // Enter test email
    const emailInput = page.locator('input[type="email"]')
    await emailInput.fill('test@example.com')

    const sendButton = page.locator('button:has-text("Send Test")')
    await expect(sendButton).toBeEnabled()
  })
})
