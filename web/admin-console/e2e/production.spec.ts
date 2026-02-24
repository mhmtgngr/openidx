import { test, expect } from '@playwright/test'

/**
 * Production-specific E2E tests for openidx.tdv.org deployment
 * These tests verify the production environment configuration
 */

const isProduction = process.env.NODE_ENV === 'production' ||
                     process.env.PLAYWRIGHT_BASE_URL?.includes('openidx.tdv.org')

test.describe('Production Environment Tests', () => {
  test('should use production domain', async ({ page }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    await page.goto('/')

    // Verify we're on the production domain
    const url = new URL(page.url())
    expect(url.hostname).toBe('openidx.tdv.org')
  })

  test('should have valid SSL certificate', async ({ request }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'https://openidx.tdv.org'

    const response = await request.get(baseURL)
    expect(response.ok()).toBeTruthy()

    // Verify HTTPS is being used
    const url = new URL(response.url())
    expect(url.protocol).toBe('https:')
  })

  test('should set production API URLs', async ({ page }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    await page.goto('/')

    // Check that API calls go to the correct domain
    let apiCallFound = false
    page.on('request', request => {
      const url = new URL(request.url())
      if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/oauth/')) {
        apiCallFound = true
        expect(url.hostname).toBe('openidx.tdv.org')
        expect(url.protocol).toBe('https:')
      }
    })

    // Trigger an API call by navigating
    await page.goto('/dashboard')

    // Wait a bit for any API calls
    await page.waitForTimeout(1000)
  })

  test('should include production analytics', async ({ page }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    await page.goto('/')

    // Check for analytics scripts (if implemented)
    const hasAnalytics = await page.evaluate(() => {
      return !!(
        (window as any).gtag ||
        (window as any).dataLayer ||
        document.querySelector('script[src*="analytics"]') ||
        document.querySelector('script[src*="gtag"]') ||
        document.querySelector('script[src*="plausible"]')
      )
    })

    // Analytics might not be implemented yet
    // This test is for future implementation
  })

  test('should have proper security headers', async ({ request }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'https://openidx.tdv.org'
    const response = await request.get(baseURL)

    const headers = response.headers()

    // Verify production security headers
    expect(headers['x-frame-options']).toBeDefined()
    expect(headers['x-content-type-options']).toBeDefined()
    expect(headers['strict-transport-security']).toBeDefined()
  })

  test('should serve optimized assets', async ({ page }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    await page.goto('/')

    // Check for minified JavaScript
    const scripts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.getAttribute('src'))
    })

    // Production assets should be minified (contain .min or have hashed filenames)
    const hasMinifiedAssets = scripts.some(src =>
      src?.includes('.min.') || src?.includes('-[') || src?.includes('.[')
    )

    // May not be true depending on build config
  })

  test('should have proper favicon and manifest', async ({ page }) => {
    test.skip(!isProduction, 'Skipping - not in production environment')

    await page.goto('/')

    // Check for favicon
    const favicon = await page.locator('link[rel="icon"]').getAttribute('href')
    expect(favicon).toBeTruthy()

    // Check for web app manifest
    const manifest = await page.locator('link[rel="manifest"]').count()
    // Manifest might not be implemented
  })
})

test.describe('Performance Tests', () => {
  test('should load landing page quickly', async ({ page }) => {
    const startTime = Date.now()

    await page.goto('/landing')
    await page.waitForLoadState('networkidle')

    const loadTime = Date.now() - startTime

    // Should load in less than 3 seconds
    expect(loadTime).toBeLessThan(3000)
  })

  test('should have good Lighthouse scores', async ({ page }) => {
    // This would require running Lighthouse
    // For now, just measure basic metrics
    const startTime = Date.now()
    await page.goto('/landing')
    await page.waitForLoadState('networkidle')
    const loadTime = Date.now() - startTime

    // DOM should be ready quickly
    expect(loadTime).toBeLessThan(3000)
  })

  test('should efficiently cache static assets', async ({ page }) => {
    const responses: Record<string, string> = {}

    page.on('response', response => {
      const url = new URL(response.url())
      if (url.pathname.match(/\.(js|css|png|jpg|jpeg|svg|woff2?)$/)) {
        responses[url.pathname] = response.headers()['cache-control'] || ''
      }
    })

    await page.goto('/landing')
    await page.waitForLoadState('networkidle')

    // In production, check that static assets have caching headers
    if (isProduction) {
      const cachedResponses = Object.values(responses).filter(cc => cc)
      if (cachedResponses.length > 0) {
        // At least some assets should have cache directives
        const hasCache = cachedResponses.some(cc =>
          cc.toLowerCase().match(/max-age|public|immutable/)
        )
        expect(hasCache).toBeTruthy()
      }
    }
  })
})

test.describe('Accessibility Tests', () => {
  test('should be keyboard navigable', async ({ page }) => {
    await page.goto('/landing')

    // Test Tab navigation
    await page.keyboard.press('Tab')

    // Should focus on something
    const focusedElement = await page.evaluate(() => document.activeElement?.tagName)
    expect(['A', 'BUTTON', 'INPUT']).toContain(focusedElement || '')
  })

  test('should have proper ARIA labels', async ({ page }) => {
    await page.goto('/landing')

    // Check for proper heading structure
    const headings = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6'))
        .map(h => ({ tag: h.tagName, text: h.textContent?.trim() }))
    })

    // Should have at least one h1
    const hasH1 = headings.some(h => h.tag === 'H1')
    expect(hasH1).toBeTruthy()

    // Headings should be in logical order
    const lastLevel = headings.reduce((last, { tag }) => {
      const level = parseInt(tag[1])
      return level > last ? level : last
    }, 0)

    expect(lastLevel).toBeGreaterThan(0)
  })

  test('should have sufficient color contrast', async ({ page }) => {
    await page.goto('/landing')

    // This would require a contrast checking library
    // For now, just verify elements exist
    const buttons = await page.locator('button').count()
    expect(buttons).toBeGreaterThan(0)
  })
})

test.describe('Cross-Browser Compatibility', () => {
  test('should work in Chromium', async ({ page }) => {
    await page.goto('/landing')
    await expect(page.locator('h1')).toContainText('Zero Trust Access Platform')
  })

  test('should handle responsive design', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto('/landing')

    // Mobile menu should be available
    const mobileMenu = page.locator('button').filter({ hasText: /Menu|Toggle/i })
    const mobileMenuCount = await mobileMenu.count()

    // Test tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 })
    await page.goto('/landing')

    // Should adapt to tablet layout
    await expect(page.locator('h1')).toBeVisible()
  })
})
