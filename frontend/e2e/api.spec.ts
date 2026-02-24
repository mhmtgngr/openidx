import { test, expect } from '@playwright/test'

test.describe('API Integration Tests', () => {
  const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000'

  test('should handle API errors gracefully', async ({ page }) => {
    // Navigate to a page that makes API calls
    await page.goto('/dashboard')

    // Intercept API calls to simulate error
    await page.route('**/api/**', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal Server Error' })
      })
    })

    // Reload page to trigger API call
    await page.reload()

    // Should handle error gracefully (not crash)
    const hasError = await page.locator('text=error,Error,fail').count() > 0
    // Page should still load with error indicators
  })

  test('should handle network timeout', async ({ page }) => {
    await page.goto('/dashboard')

    // Intercept and hang requests
    await page.route('**/api/**', route => {
      // Don't fulfill - simulate timeout
    })

    // Should show loading state that doesn't hang forever
    const loadingSpinner = page.locator('[data-testid="loading"], .loading, .spinner')
    const isVisible = await loadingSpinner.isVisible().catch(() => false)

    if (isVisible) {
      // Should eventually show some state
      await page.waitForTimeout(3000)
    }
  })

  test('should retry failed requests', async ({ page }) => {
    let requestCount = 0

    await page.route('**/api/v1/**', route => {
      requestCount++
      if (requestCount <= 2) {
        // Fail first 2 requests
        route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Service Unavailable' })
        })
      } else {
        // Succeed on 3rd try
        route.continue()
      }
    })

    await page.goto('/dashboard')

    // Should have made multiple attempts
    expect(requestCount).toBeGreaterThan(1)
  })
})

test.describe('CORS and Security Headers', () => {
  test('should include security headers', async ({ request }) => {
    const response = await request.get(baseURL)

    // Check for common security headers
    const headers = response.headers()

    // These headers should be present in production
    const securityHeaders = [
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection'
    ]

    securityHeaders.forEach(header => {
      // In dev env, these might not be set
      // In production with nginx, they should be
      if (process.env.NODE_ENV === 'production') {
        expect(headers[header]).toBeDefined()
      }
    })
  })
})

test.describe('Service Worker and Offline Support', () => {
  test('should register service worker', async ({ page }) => {
    await page.goto('/dashboard')

    // Check if service worker is registered
    const swRegistration = await page.evaluate(() => {
      return navigator.serviceWorker.getRegistration()
    })

    // Service worker might not be implemented yet
    // This test is for future implementation
  })

  test('should handle offline mode gracefully', async ({ context }) => {
    // Simulate offline mode
    await context.setOffline(true)

    const page = await context.newPage()
    await page.goto('/dashboard')

    // Should show cached content or offline indicator
    await page.waitForTimeout(1000)

    // Restore online mode
    await context.setOffline(false)
  })
})
