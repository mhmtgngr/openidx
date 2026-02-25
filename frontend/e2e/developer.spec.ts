import { test, expect } from '@playwright/test'

test.describe('API Explorer', () => {
  test('should display API explorer page', async ({ page }) => {
    await page.goto('/api-explorer')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('API Explorer')
  })
})

test.describe('OAuth Playground', () => {
  test('should display OAuth playground page', async ({ page }) => {
    await page.goto('/oauth-playground')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('OAuth Playground')
  })
})

test.describe('Developer Settings', () => {
  test('should display developer settings page', async ({ page }) => {
    await page.goto('/developer-settings')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Developer Settings')
  })
})

test.describe('Error Catalog', () => {
  test('should display error catalog page', async ({ page }) => {
    await page.goto('/error-catalog')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Error Catalog')
  })
})

test.describe('API Docs', () => {
  test('should display API documentation page', async ({ page }) => {
    await page.goto('/api-docs')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1, h2')).toContainText('API', { timeout: 5000 })
  })
})
