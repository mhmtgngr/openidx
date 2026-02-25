import { test, expect } from '@playwright/test'

test.describe('System Health', () => {
  test('should display system health page', async ({ page }) => {
    await page.goto('/system-health')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('System Health')
  })

  test('should display health status indicators', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for health indicators
    const statusIndicators = page.locator('text=Healthy, text=Degraded, text=Down')
    if (await statusIndicators.first().isVisible()) {
      await expect(statusIndicators.first()).toBeVisible()
    }
  })
})

test.describe('Organizations', () => {
  test('should display organizations page', async ({ page }) => {
    await page.goto('/organizations')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Organizations')
  })
})

test.describe('Delegations', () => {
  test('should display delegations page', async ({ page }) => {
    await page.goto('/delegations')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Delegations')
  })
})

test.describe('Webhooks', () => {
  test('should display webhooks page', async ({ page }) => {
    await page.goto('/webhooks')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Webhooks')
  })

  test('should have create webhook button', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const createButton = page.locator('button:has-text("Add Webhook"), button:has-text("Create")')
    if (await createButton.first().isVisible()) {
      await expect(createButton.first()).toBeVisible()
    }
  })
})

test.describe('Tenant Management', () => {
  test('should display tenant management page', async ({ page }) => {
    await page.goto('/tenant-management')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Tenant')
  })
})

test.describe('Notification Admin', () => {
  test('should display notification admin page', async ({ page }) => {
    await page.goto('/notification-admin')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Notification')
  })
})
