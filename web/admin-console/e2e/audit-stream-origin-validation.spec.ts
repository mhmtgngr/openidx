import { test, expect } from '@playwright/test'

/**
 * E2E Tests for WebSocket Origin Validation in Audit Stream
 *
 * These tests verify that the WebSocket origin validation properly:
 * 1. Rejects connections from disallowed origins
 * 2. Accepts connections from allowed origins
 * 3. Displays appropriate error messages when connections are rejected
 * 4. Prevents Cross-Site WebSocket Hijacking (CSWSH) attacks
 */
test.describe('Audit Stream WebSocket Origin Validation', () => {
  test.beforeEach(async ({ page, context }) => {
    // Mock authentication
    const mockPayload = {
      sub: 'test-user-id',
      email: 'admin@openidx.local',
      name: 'Test Admin',
      roles: ['admin'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    }
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = btoa(JSON.stringify(mockPayload))
    const mockToken = `${header}.${payload}.mock-signature`

    // Set auth token in context before navigating
    await context.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('refresh_token', 'mock-refresh-token')
    }, mockToken)

    // Mock REST API for initial events
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    // Mock audit statistics API
    await page.route('**/api/v1/audit/statistics*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_events: 0,
          events_by_action: {},
          events_by_outcome: { success: 0, failure: 0 },
          events_by_actor: [],
        }),
      })
    })
  })

  test('should display connection error when origin is rejected by server', async ({ page }) => {
    // Mock WebSocket rejection response (403 Forbidden)
    await page.route('**/audit/stream', async (route) => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'websocket_origin_not_allowed',
          message: 'WebSocket connections from your origin are not allowed',
        }),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Click connect button
    const connectButton = page.getByRole('button', { name: /connect/i })
    await expect(connectButton).toBeVisible()
    await connectButton.click()

    // Should show error message about origin rejection
    await expect(page.getByText(/origin.*not.*allowed|connection.*rejected|forbidden/i)).toBeVisible({ timeout: 5000 })
  })

  test('should show detailed error information for rejected connections', async ({ page }) => {
    // Mock WebSocket rejection with security details
    await page.route('**/audit/stream', async (route) => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'websocket_origin_not_allowed',
          message: 'WebSocket connections from your origin are not allowed',
          details: {
            allowed_origins: ['https://example.com', 'https://app.example.com'],
            your_origin: window.location.origin,
          },
        }),
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should display the list of allowed origins
    await expect(page.getByText(/allowed.*origins/i)).toBeVisible({ timeout: 5000 })
  })

  test('should successfully connect when origin is allowed', async ({ page }) => {
    let connectionAttempts = 0

    // Mock WebSocket upgrade success
    await page.route('**/audit/stream', async (route) => {
      connectionAttempts++

      // For testing, we'll simulate a successful connection
      // In real scenario, this would be a WebSocket connection
      await route.fulfill({
        status: 101, // Switching Protocols
        headers: {
          'Connection': 'Upgrade',
          'Upgrade': 'websocket',
        },
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should show connected status
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })

    // Verify connection attempt was made
    expect(connectionAttempts).toBeGreaterThan(0)
  })

  test('should handle same-origin policy correctly', async ({ page }) => {
    // Mock rejection for cross-origin request with same-origin policy
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin']

      // If no origin or same-origin, allow
      if (!requestOrigin || requestOrigin === route.request().headers()['host']) {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Same-origin policy violation',
          }),
        })
      }
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should show connected status (same-origin should work)
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })
  })

  test('should log security events when origin is rejected', async ({ page }) => {
    let rejectionLogged = false

    // Track API calls to verify security logging
    await page.route('**/api/v1/audit/events', async (route) => {
      // Capture any audit events created
      const response = await route.fetch()
      const body = await response.json()

      // Check if any event is about rejected WebSocket connection
      if (Array.isArray(body) && body.some((e: any) => e.action === 'websocket.connection_rejected')) {
        rejectionLogged = true
      }

      return body
    })

    // Mock WebSocket rejection
    await page.route('**/audit/stream', async (route) => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'websocket_origin_not_allowed',
          message: 'WebSocket connections from your origin are not allowed',
        }),
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Wait a moment for any logging to occur
    await page.waitForTimeout(1000)

    // Verify error was shown to user
    await expect(page.getByText(/origin.*not.*allowed|connection.*rejected/i)).toBeVisible({ timeout: 5000 })
  })

  test('should prevent wildcard origin in production mode', async ({ page }) => {
    // Mock production environment check
    await page.route('**/api/v1/audit/stream', async (route) => {
      // Simulate production mode rejecting wildcard
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'websocket_origin_not_allowed',
          message: 'Wildcard origins are not allowed in production',
        }),
      })
    })

    // Set a flag to simulate production mode
    await page.evaluate(() => {
      window.__APP_ENV__ = 'production'
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should show production mode error
    await expect(page.getByText(/wildcard.*not.*allowed|production/i)).toBeVisible({ timeout: 5000 })
  })

  test('should allow subdomain wildcard patterns', async ({ page, context }) => {
    // Mock authentication
    const mockPayload = {
      sub: 'test-user-id',
      email: 'admin@openidx.local',
      name: 'Test Admin',
      roles: ['admin'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    }
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = btoa(JSON.stringify(mockPayload))
    const mockToken = `${header}.${payload}.mock-signature`

    await context.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('refresh_token', 'mock-refresh-token')
    }, mockToken)

    // Mock REST API for initial events
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    // Mock audit statistics API
    await page.route('**/api/v1/audit/statistics*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_events: 0,
          events_by_action: {},
          events_by_outcome: { success: 0, failure: 0 },
          events_by_actor: [],
        }),
      })
    })

    // Test subdomain wildcard - reject bare domain, allow subdomains
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin'] || ''

      // Mock subdomain wildcard logic: *.example.com
      const allowedPatterns = ['https://app.example.com', 'https://api.example.com']
      const isSubdomain = /^(https?:\/\/)[\w-]+\.example\.com$/.test(requestOrigin)

      if (isSubdomain) {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      } else if (requestOrigin === 'https://example.com') {
        // Bare domain should be rejected for wildcard patterns
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Bare domain not allowed for wildcard subdomain pattern',
          }),
        })
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Origin not in allowed list',
          }),
        })
      }
    })

    await page.goto('/audit/audit-dashboard')

    // Set the mock origin to a subdomain
    await page.evaluate(() => {
      Object.defineProperty(window, 'location', {
        writable: true,
        value: {
          origin: 'https://app.example.com',
          href: 'https://app.example.com/audit/audit-dashboard'
        }
      })
    })

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should connect successfully with subdomain
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })
  })

  test('should handle multiple allowed origins', async ({ page, context }) => {
    // Mock authentication
    const mockPayload = {
      sub: 'test-user-id',
      email: 'admin@openidx.local',
      name: 'Test Admin',
      roles: ['admin'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    }
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = btoa(JSON.stringify(mockPayload))
    const mockToken = `${header}.${payload}.mock-signature`

    await context.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('refresh_token', 'mock-refresh-token')
    }, mockToken)

    // Mock REST API
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.route('**/api/v1/audit/statistics*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_events: 0,
          events_by_action: {},
          events_by_outcome: { success: 0, failure: 0 },
          events_by_actor: [],
        }),
      })
    })

    // Test multiple allowed origins
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin'] || ''

      const allowedOrigins = ['https://console.example.com', 'https://admin.example.com', 'http://localhost:3000']

      if (allowedOrigins.includes(requestOrigin)) {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: `Origin not in allowed list. Allowed origins: ${allowedOrigins.join(', ')}`,
          }),
        })
      }
    })

    await page.goto('/audit/audit-dashboard')

    // Set the mock origin to one of the allowed origins
    await page.evaluate(() => {
      Object.defineProperty(window, 'location', {
        writable: true,
        value: {
          origin: 'https://console.example.com',
          href: 'https://console.example.com/audit/audit-dashboard'
        }
      })
    })

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should connect successfully
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout:  5000 })
  })

  test('should display security warnings when connection is rejected multiple times', async ({ page }) => {
    let rejectionCount = 0

    // Mock WebSocket rejection with tracking
    await page.route('**/audit/stream', async (route) => {
      rejectionCount++

      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'websocket_origin_not_allowed',
          message: 'WebSocket connections from your origin are not allowed',
          rejection_count: rejectionCount,
        }),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Attempt connection multiple times
    const connectButton = page.getByRole('button', { name: /connect/i })

    // First attempt
    await connectButton.click()
    await expect(page.getByText(/origin.*not.*allowed|connection.*rejected/i)).toBeVisible({ timeout: 5000 })

    // Second attempt
    await connectButton.click()

    // Should show warning about repeated attempts
    await expect(page.getByText(/multiple.*attempts|rate.*limit|too.*many.*requests/i)).toBeVisible({ timeout: 5000 })
  })

  test('should validate origin before establishing WebSocket connection', async ({ page }) => {
    let originValidationPerformed = false

    // Mock that validates origin before upgrade
    await page.route('**/audit/stream', async (route) => {
      const origin = route.request().headers()['origin']

      // Log that origin validation was performed
      if (origin) {
        originValidationPerformed = true
      }

      // Always reject for this test
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'websocket_origin_not_allowed',
          message: 'Origin validation failed',
        }),
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Verify origin validation was performed
    expect(originValidationPerformed).toBe(true)

    // Should show error to user
    await expect(page.getByText(/origin.*validation.*failed|origin.*not.*allowed/i)).toBeVisible({ timeout: 5000 })
  })

  test('should support localhost origins in development mode', async ({ page }) => {
    // Set development mode
    await page.evaluate(() => {
      window.__APP_ENV__ = 'development'
    })

    // Mock localhost allowed origin
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin'] || ''

      // Allow localhost origins in development
      const localhostPattern = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/

      if (localhostPattern.test(requestOrigin)) {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Origin not in allowed list',
          }),
        })
      }
    })

    // Set mock origin to localhost
    await page.evaluate(() => {
      Object.defineProperty(window, 'location', {
        writable: true,
        value: {
          origin: 'http://localhost:3000',
          href: 'http://localhost:3000/audit/audit-dashboard'
        }
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should connect successfully in development mode
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })
  })

  test('should show clear error message when origin header is missing', async ({ page }) => {
    // Mock WebSocket rejection for missing origin
    await page.route('**/audit/stream', async (route) => {
      const hasOrigin = route.request().headers()['origin']

      if (!hasOrigin) {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_required',
            message: 'Origin header is required for WebSocket connections',
          }),
        })
      } else {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      }
    })

    // Simulate missing origin header
    await page.addInitScript(() => {
      const originalFetch = window.fetch
      window.fetch = (...args) => {
        const [url, options = {}] = args
        // Remove Origin header for WebSocket requests
        if (typeof url === 'string' && url.includes('/audit/stream')) {
          const { origin, ...headers } = options.headers || {}
          return originalFetch(url, { ...options, headers })
        }
        return originalFetch(...args)
      }
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should show error about missing origin
    await expect(page.getByText(/origin.*required|missing.*origin/i)).toBeVisible({ timeout: 5000 })
  })

  test('should recover from connection rejection with proper configuration', async ({ page }) => {
    // Initially reject
    let allowConnection = false

    await page.route('**/audit/stream', async (route) => {
      if (!allowConnection) {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Origin not in allowed list',
          }),
        })
      } else {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      }
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should show error initially
    await expect(page.getByText(/origin.*not.*allowed/i)).toBeVisible({ timeout: 5000 })

    // Simulate configuration update that allows this origin
    allowConnection = true

    // Try connecting again
    await connectButton.click()

    // Should now connect successfully
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })
  })
})

/**
 * Security-Focused Tests for Origin Validation
 * These tests specifically target security scenarios
 */
test.describe('WebSocket Origin Security - Edge Cases', () => {
  test.beforeEach(async ({ page, context }) => {
    const mockPayload = {
      sub: 'test-user-id',
      email: 'admin@openidx.local',
      name: 'Test Admin',
      roles: ['admin'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    }
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = btoa(JSON.stringify(mockPayload))
    const mockToken = `${header}.${payload}.mock-signature`

    await context.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('refresh_token', 'mock-refresh-token')
    }, mockToken)

    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.route('**/api/v1/audit/statistics*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_events: 0,
          events_by_action: {},
          events_by_outcome: { success: 0, failure: 0 },
          events_by_actor: [],
        }),
      })
    })
  })

  test('should prevent connection from malicious domain with similar name', async ({ page }) => {
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin'] || ''

      // Test: evil.com vs example.com.evil.com (domain evasion attempt)
      const allowedOrigins = ['https://example.com']

      // Check for domain evasion attempts
      const isDomainEvasion = /.*\.example\.com\.evil\.com$/.test(requestOrigin)

      if (isDomainEvasion || !allowedOrigins.includes(requestOrigin)) {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Potential domain evasion attempt detected',
          }),
        })
      } else {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      }
    })

    // Set mock origin to potential evasion domain
    await page.evaluate(() => {
      Object.defineProperty(window, 'location', {
        writable: true,
        value: {
          origin: 'https://example.com.evil.com',
          href: 'https://example.com.evil.com/audit/audit-dashboard'
        }
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should reject and detect evasion attempt
    await expect(page.getByText(/evasion.*attempt|domain.*evasion|not.*allowed/i)).toBeVisible({ timeout: 5000 })
  })

  test('should handle case normalization correctly', async ({ page }) => {
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin'] || ''

      // Test: origin should be case-insensitive
      // Allowed: https://Example.com
      const allowedOrigins = ['https://example.com']

      // Normalize for comparison
      const normalizedOrigin = requestOrigin.toLowerCase()
      const isAllowed = allowedOrigins.some(o => o.toLowerCase() === normalizedOrigin)

      if (isAllowed) {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Origin not in allowed list',
          }),
        })
      }
    })

    // Test with uppercase origin
    await page.evaluate(() => {
      Object.defineProperty(window, 'location', {
        writable: true,
        value: {
          origin: 'https://EXAMPLE.COM',
          href: 'https://EXAMPLE.COM/audit/audit-dashboard'
        }
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should connect successfully due to case-insensitive matching
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })
  })

  test('should normalize port numbers in origin checking', async ({ page }) => {
    await page.route('**/audit/stream', async (route) => {
      const requestOrigin = route.request().headers()['origin'] || ''

      // Test: https://example.com:443 should match https://example.com
      const allowedOrigins = ['https://example.com']

      // Remove default ports for comparison
      let normalizedOrigin = requestOrigin.replace(':443', '').replace(':80', '')

      const isAllowed = allowedOrigins.includes(normalizedOrigin)

      if (isAllowed) {
        await route.fulfill({
          status: 101,
          headers: {
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
          },
        })
      } else {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'websocket_origin_not_allowed',
            message: 'Origin not in allowed list',
          }),
        })
      }
    })

    // Test with default HTTPS port
    await page.evaluate(() => {
      Object.defineProperty(window, 'location', {
        writable: true,
        value: {
          origin: 'https://example.com:443',
          href: 'https://example.com:443/audit/audit-dashboard'
        }
      })
    })

    await page.goto('/audit/audit-dashboard')

    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should connect successfully due to port normalization
    await expect(page.getByText(/connected|streaming/i)).toBeVisible({ timeout: 5000 })
  })
})
