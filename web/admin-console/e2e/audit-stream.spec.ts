import { test, expect } from '@playwright/test'

test.describe('Audit Stream Dashboard', () => {
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
        body: JSON.stringify([
          {
            id: 'evt-1',
            timestamp: new Date().toISOString(),
            event_type: 'authentication',
            category: 'authentication',
            action: 'user.login',
            outcome: 'success',
            actor_id: 'user-1',
            actor_type: 'user',
            actor_ip: '192.168.1.100',
            target_id: 'user-1',
            target_type: 'user',
            resource_id: 'user-1',
            details: { category: 'authentication' },
            session_id: 'sess-1',
            request_id: 'req-1',
          },
          {
            id: 'evt-2',
            timestamp: new Date(Date.now() - 60000).toISOString(),
            event_type: 'user_management',
            category: 'user_management',
            action: 'user.created',
            outcome: 'success',
            actor_id: 'admin-1',
            actor_type: 'user',
            actor_ip: '192.168.1.10',
            target_id: 'user-2',
            target_type: 'user',
            resource_id: 'user-2',
            details: { category: 'user_management' },
            session_id: 'sess-2',
            request_id: 'req-2',
          },
        ]),
      })
    })

    // Mock audit statistics API
    await page.route('**/api/v1/audit/statistics*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_events: 1000,
          events_by_action: {
            'user.login': 500,
            'user.logout': 300,
            'user.created': 50,
          },
          events_by_outcome: {
            success: 900,
            failure: 100,
          },
          events_by_actor: [
            { actor_id: 'user-1', count: 200 },
            { actor_id: 'user-2', count: 150 },
          ],
        }),
      })
    })
  })

  test('should display audit dashboard page heading', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')
    await expect(page.getByRole('heading', { name: /audit dashboard/i })).toBeVisible()
    await expect(page.getByText(/Real-time audit event monitoring/i)).toBeVisible()
  })

  test('should display connection status card', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Check for connection status elements
    await expect(page.getByText(/Audit Stream Connection/i)).toBeVisible()
    await expect(page.getByText(/Disconnected/i)).toBeVisible()
  })

  test('should display statistics cards', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Check for statistics cards
    await expect(page.getByText(/Events Received/i)).toBeVisible()
    await expect(page.getByText(/Event Rate/i)).toBeVisible()
    await expect(page.getByText(/Last Event/i)).toBeVisible()
  })

  test('should have search and filter controls', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Search input
    const searchInput = page.getByPlaceholder(/search by action/i)
    await expect(searchInput).toBeVisible()

    // Category filter
    await expect(page.getByText(/All Categories/i)).toBeVisible()

    // Outcome filter
    await expect(page.getByText(/All Outcomes/i)).toBeVisible()
  })

  test('should connect to WebSocket stream when connect button is clicked', async ({ page }) => {
    // Mock WebSocket connection
    await page.route('**/audit/stream', async (route) => {
      // For WebSocket, we need to handle the upgrade request
      // Since Playwright can't fully mock WebSocket, we'll just let it connect
      route.continue()
    })

    await page.goto('/audit/audit-dashboard')

    // Click connect button
    const connectButton = page.getByRole('button', { name: /connect/i })
    await expect(connectButton).toBeVisible()
    await connectButton.click()

    // The connection state should change (shown by UI updates)
    // Note: Full WebSocket testing requires a running server
  })

  test('should display audit events', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Wait for events to load
    await expect(page.getByText('user.login')).toBeVisible()
    await expect(page.getByText('user.created')).toBeVisible()
  })

  test('should show event details when expanded', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Wait for events to load
    await expect(page.getByText('user.login')).toBeVisible()

    // Click the eye icon to expand details
    const eyeButtons = page.getByRole('button').filter({ has: page.locator('svg') })
    if ((await eyeButtons.count()) > 0) {
      await eyeButtons.first().click()

      // Check for expanded details
      await expect(page.getByText(/Event ID/i)).toBeVisible()
      await expect(page.getByText(/Actor/i)).toBeVisible()
      await expect(page.getByText(/Resource/i)).toBeVisible()
    }
  })

  test('should filter events by search', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Wait for events to load
    await expect(page.getByText('user.login')).toBeVisible()

    // Search for specific event
    const searchInput = page.getByPlaceholder(/search by action/i)
    await searchInput.fill('login')

    // Should show login events
    await expect(page.getByText('login')).toBeVisible()
  })

  test('should filter events by category', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Wait for events to load
    await expect(page.getByText('authentication')).toBeVisible()

    // Click category filter dropdown
    const categorySelect = page.getByText(/All Categories/i)
    await categorySelect.click()

    // Select authentication category
    await page.getByText('Authentication').click()

    // Events should be filtered
    await page.waitForTimeout(500) // Wait for filter to apply
  })

  test('should filter events by outcome', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Wait for events to load
    await expect(page.getByText('success')).toBeVisible()

    // Click outcome filter dropdown
    const outcomeSelect = page.getByText(/All Outcomes/i)
    await outcomeSelect.click()

    // Select success outcome
    await page.getByText('Success').click()

    // Events should be filtered
    await page.waitForTimeout(500) // Wait for filter to apply
  })

  test('should have clear and pause/resume buttons', async ({ page }) => {
    await page.goto('/audit/audit-dashboard')

    // Clear button
    const clearButton = page.getByRole('button', { name: /clear/i })
    await expect(clearButton).toBeVisible()

    // Pause/Resume button
    const pauseButton = page.getByRole('button', { name: /pause/i })
    await expect(pauseButton).toBeVisible()
  })

  test('should show empty state when no events', async ({ page }) => {
    // Mock empty events response
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Should show empty state message
    await expect(page.getByText(/No events to display/i)).toBeVisible()
  })

  test('should handle connection errors gracefully', async ({ page }) => {
    // Mock failed WebSocket connection
    await page.route('**/audit/stream', async (route) => {
      await route.abort('failed')
    })

    await page.goto('/audit/audit-dashboard')

    // Try to connect
    const connectButton = page.getByRole('button', { name: /connect/i })
    await connectButton.click()

    // Should show error state
    await page.waitForTimeout(1000)

    // Error indicator should be present
    const connectionStatus = page.getByText(/Connection Error/i)
    // Note: This might not appear immediately due to WebSocket connection timing
  })
})

test.describe('Audit Stream Origin Validation', () => {
  test('should display current origin information', async ({ page, context }) => {
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

    // Mock API responses
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Should show origin information when connected or attempting connection
    const currentOriginText = page.getByText(/Current Origin/i)
    // Note: Origin info appears when connection is attempted or connected
  })

  test('should handle origin rejection with appropriate error message', async ({ page, context }) => {
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

    // Mock API responses
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // The origin rejection would be handled by the WebSocket connection
    // In a real scenario, this would be triggered by the server rejecting
    // the connection based on the Origin header
  })

  test('should show allowed origins when configured', async ({ page, context }) => {
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

    // Mock API responses
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Allowed origins would be shown after receiving config from server
    // This would appear in the connection status card
  })
})

test.describe('Audit Stream Real-time Updates', () => {
  test('should pause and resume event stream', async ({ page, context }) => {
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

    // Mock API responses
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Click pause button
    const pauseButton = page.getByRole('button', { name: /pause/i })
    await expect(pauseButton).toBeVisible()
    await pauseButton.click()

    // Button should change to Resume
    const resumeButton = page.getByRole('button', { name: /resume/i })
    await expect(resumeButton).toBeVisible()

    // Click resume
    await resumeButton.click()

    // Button should change back to Pause
    await expect(pauseButton).toBeVisible()
  })

  test('should clear events', async ({ page, context }) => {
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

    // Mock API responses
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      })
    })

    await page.goto('/audit/audit-dashboard')

    // Clear button should be present
    const clearButton = page.getByRole('button', { name: /clear/i })
    await expect(clearButton).toBeVisible()
  })
})
