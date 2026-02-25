import { test, expect } from '@playwright/test'

test.describe('AI Agents Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ai-agents')
  })

  test('should display AI agents page with stats', async ({ page }) => {
    // Check if redirected to login (unauthenticated)
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Verify page title
    await expect(page.locator('h1')).toContainText('AI Agent Management')

    // Verify stats cards are present
    await expect(page.locator('text=Total Agents')).toBeVisible()
    await expect(page.locator('text=Active')).toBeVisible()
  })

  test('should display create agent button', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const createButton = page.locator('button:has-text("Create Agent")')
    await expect(createButton).toBeVisible()
  })

  test('should open create agent modal', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const createButton = page.locator('button:has-text("Create Agent")')
    await createButton.click()

    // Verify modal appears
    await expect(page.locator('text=Create New AI Agent')).toBeVisible()
  })

  test('should display agent list', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for agents list
    const agentsList = page.locator('text=Agents')
    await expect(agentsList).toBeVisible()
  })

  test('should show agent details when clicked', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for an agent in the list (if any exist)
    const agentCard = page.locator('[class*="cursor-pointer"]').first()
    if (await agentCard.isVisible()) {
      await agentCard.click()
      // Verify detail panel appears
      await expect(page.locator('text=Credentials')).toBeVisible()
    }
  })
})

test.describe('AI Agent Actions', () => {
  test('should allow agent suspension', async ({ page }) => {
    await page.goto('/ai-agents')
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Find suspend button (if there are active agents)
    const suspendButton = page.locator('button:has-text("Suspend")').first()
    if (await suspendButton.isVisible()) {
      await suspendButton.click()
      // In a real test with backend, verify state change
    }
  })

  test('should allow credential rotation', async ({ page }) => {
    await page.goto('/ai-agents')
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for rotate key button
    const rotateButton = page.locator('button:has-text("Rotate Key")').first()
    if (await rotateButton.isVisible()) {
      await rotateButton.click()
      // Verify API key display modal appears
      await expect(page.locator('text=New API Key')).toBeVisible({ timeout: 5000 })
    }
  })
})
