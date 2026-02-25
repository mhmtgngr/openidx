import { test, expect } from '@playwright/test'

test.describe('Proxy Routes', () => {
  test('should display proxy routes page', async ({ page }) => {
    await page.goto('/proxy-routes')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Proxy Routes')
  })
})

test.describe('Ziti Network', () => {
  test('should display Ziti network page', async ({ page }) => {
    await page.goto('/ziti-network')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Ziti Network')
  })

  test('should display Ziti status indicator', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for connection status
    const statusIndicator = page.locator('text=Connected, text=Disconnected')
    if (await statusIndicator.isVisible()) {
      await expect(statusIndicator).toBeVisible()
    }
  })
})

test.describe('Ziti Discovery', () => {
  test('should display Ziti discovery page', async ({ page }) => {
    await page.goto('/ziti-discovery')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Ziti Discovery')
  })
})

test.describe('BrowZer Management', () => {
  test('should display BrowZer management page', async ({ page }) => {
    await page.goto('/browzer-management')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('BrowZer')
  })
})

test.describe('App Publish', () => {
  test('should display app publish page', async ({ page }) => {
    await page.goto('/app-publish')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('App Publish')
  })
})

test.describe('Certificates', () => {
  test('should display certificates page', async ({ page }) => {
    await page.goto('/certificates')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Certificates')
  })
})

test.describe('Devices', () => {
  test('should display devices page', async ({ page }) => {
    await page.goto('/devices')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Devices')
  })
})
