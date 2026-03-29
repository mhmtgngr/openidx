import { test, expect } from '@playwright/test'

test.describe('API Explorer', () => {
  test('should display API explorer page', async ({ page, context }) => {
    await context.addInitScript(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto('/api-explorer')

    // Wait for either redirect to login or page to load
    await page.waitForURL({ url: /\/login|\/api-explorer/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('API Explorer')
  })
})

test.describe('OAuth Playground', () => {
  test('should display OAuth playground page', async ({ page, context }) => {
    await context.addInitScript(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto('/oauth-playground')

    // Wait for either redirect to login or page to load
    await page.waitForURL({ url: /\/login|\/oauth-playground/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('OAuth Playground')
  })
})

test.describe('Developer Settings', () => {
  test('should display developer settings page', async ({ page, context }) => {
    await context.addInitScript(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto('/developer-settings')

    // Wait for either redirect to login or page to load
    await page.waitForURL({ url: /\/login|\/developer-settings/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Developer Settings')
  })
})

test.describe('Error Catalog', () => {
  test('should display error catalog page', async ({ page, context }) => {
    await context.addInitScript(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto('/error-catalog')

    // Wait for either redirect to login or page to load
    await page.waitForURL({ url: /\/login|\/error-catalog/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Error Catalog')
  })
})

test.describe('API Docs', () => {
  test('should display API documentation page', async ({ page, context }) => {
    await context.addInitScript(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto('/api-docs')

    // Wait for either redirect to login or page to load
    await page.waitForURL({ url: /\/login|\/api-docs/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1, h2')).toContainText('API', { timeout: 5000 })
  })
})
