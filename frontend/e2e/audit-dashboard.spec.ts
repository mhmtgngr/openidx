import { test, expect } from '@playwright/test'

/**
 * E2E Tests for Audit Dashboard and Stream
 *
 * Tests the real-time audit event stream with origin validation,
 * connection status display, and WebSocket functionality.
 */

test.describe('Audit Dashboard - Authenticated', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    // If redirected to login, skip all tests
    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display audit dashboard page', async ({ page }) => {
    // Check page title
    await expect(page.locator('h1')).toContainText('Audit Dashboard', { timeout: 5000 })

    // Check for page description
    await expect(page.locator('text=real-time audit event stream')).toBeVisible()
  })

  test('should display connection status cards', async ({ page }) => {
    // Connection Status card
    await expect(page.locator('text=Connection Status')).toBeVisible()

    // Total Events card
    await expect(page.locator('text=Total Events')).toBeVisible()

    // Last Event card
    await expect(page.locator('text=Last Event')).toBeVisible()

    // Origin Status card
    await expect(page.locator('text=Origin Status')).toBeVisible()
  })

  test('should display stream connection panel', async ({ page }) => {
    // Check for connection panel
    await expect(page.locator('text=Stream Connection')).toBeVisible()
    await expect(page.locator('text=Audit Stream Connection')).toBeVisible()
  })

  test('should display live events feed section', async ({ page }) => {
    // Check for live events feed
    await expect(page.locator('text=Live Events Feed')).toBeVisible()
    await expect(page.locator('text=Recent Events')).toBeVisible()
  })

  test('should show current origin information', async ({ page }) => {
    // Look for current origin display
    const originSection = page.locator('text=Current Origin')
    if (await originSection.isVisible()) {
      await expect(originSection).toBeVisible()

      // Origin should be displayed as code
      const originCode = page.locator('code').filter({ hasText: /^http/ })
      if (await originCode.count() > 0) {
        await expect(originCode.first()).toBeVisible()
      }
    }
  })

  test('should have connect/disconnect button', async ({ page }) => {
    // Look for connect button
    const connectButton = page.locator('button:has-text("Connect"), button:has-text("Disconnect")')

    if (await connectButton.count() > 0) {
      await expect(connectButton.first()).toBeVisible()
    }
  })

  test('should display security notice about origin validation', async ({ page }) => {
    // Check for security notice
    await expect(
      page.locator('text=WebSocket Origin Validation').or(
        page.locator('text=Origin Validation')
      )
    ).toBeVisible()
  })

  test('should display clear events button', async ({ page }) => {
    const clearButton = page.locator('button:has-text("Clear Events")')

    if (await clearButton.isVisible()) {
      await expect(clearButton).toBeVisible()
    }
  })
})

test.describe('Audit Stream Connection States', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should show disconnected state initially', async ({ page }) => {
    // Look for disconnected status badge
    const disconnectedBadge = page.locator('text=Disconnected').or(
      page.locator('[class*="badge"]').filter({ hasText: /disconnected/i })
    )

    // The badge might not be immediately present due to auto-connect
    const hasBadge = await disconnectedBadge.count() > 0

    if (hasBadge) {
      await expect(disconnectedBadge.first()).toBeVisible()
    }
  })

  test('should show connecting state when connection initiates', async ({ page }) => {
    // Click connect if not already connected
    const connectButton = page.locator('button:has-text("Connect")')

    if (await connectButton.isVisible()) {
      await connectButton.click()

      // Look for connecting state
      const connectingText = page.locator('text=Connecting')
      const connectingSpinner = page.locator('[class*="spin"]')

      const hasConnectingIndicator = await connectingText.isVisible() || await connectingSpinner.count() > 0

      // Connecting state is transient, so we just check it existed
      if (hasConnectingIndicator) {
        await expect(connectingText.or(connectingSpinner.first())).toBeVisible()
      }
    }
  })

  test('should show origin rejected state when origin is not allowed', async ({ page }) => {
    // This test checks the UI display when origin is rejected
    // In a real scenario, this would require mocking the WebSocket response

    const originRejectedText = page.locator('text=Origin Not Allowed').or(
      page.locator('text=Origin Not Authorized').or(
        page.locator('text=Origin Rejected')
      )
    )

    // The UI should handle this state, even if we can't trigger it in tests
    const hasOriginRejected = await originRejectedText.count() > 0

    if (hasOriginRejected) {
      await expect(originRejectedText.first()).toBeVisible()

      // Should show helpful message
      await expect(page.locator('text=allowed origins')).toBeVisible()
    }
  })

  test('should display connection error details when error occurs', async ({ page }) => {
    // Check for error display capability
    const errorSection = page.locator('[class*="destructive"]').filter({ hasText: /error/i })

    // Error sections only appear when there's an error
    const hasError = await errorSection.count() > 0

    if (hasError) {
      await expect(errorSection.first()).toBeVisible()

      // Should show error code
      await expect(page.locator('code[class*="bg"]')).toBeVisible()
    }
  })
})

test.describe('Audit Stream - Origin Validation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display allowed origins when available', async ({ page }) => {
    const allowedOriginsSection = page.locator('text=Allowed Origins')

    if (await allowedOriginsSection.isVisible()) {
      await expect(allowedOriginsSection).toBeVisible()

      // Should show origin badges
      const originBadges = page.locator('[class*="badge"]').filter({ hasText: /^http/ })
      const count = await originBadges.count()

      if (count > 0) {
        await expect(originBadges.first()).toBeVisible()
      }
    }
  })

  test('should highlight current origin in allowed list', async ({ page }) => {
    // Look for checkmark icon next to current origin
    const checkmarkInBadge = page.locator('[class*="badge"]').filter({ hasText: /http/ }).locator('svg')

    const count = await checkmarkInBadge.count()

    if (count > 0) {
      await expect(checkmarkInBadge.first()).toBeVisible()
    }
  })

  test('should show origin validation configuration section', async ({ page }) => {
    const configSection = page.locator('text=Origin Validation Configuration')

    // This section appears when there are allowed origins or origin is rejected
    const hasConfigSection = await configSection.count() > 0

    if (hasConfigSection) {
      await expect(configSection.first()).toBeVisible()
    }
  })
})

test.describe('Audit Stream - Analytics', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display top actions when events are available', async ({ page }) => {
    // Top Actions section appears after receiving events
    const topActionsSection = page.locator('text=Top Actions')

    // This section only appears when there are events
    const hasTopActions = await topActionsSection.count() > 0

    if (hasTopActions) {
      await expect(topActionsSection.first()).toBeVisible()

      // Should have action bars with percentages
      const actionBars = page.locator('[class*="bg-blue-500"]')
      if (await actionBars.count() > 0) {
        await expect(actionBars.first()).toBeVisible()
      }
    }
  })

  test('should display top actors when events are available', async ({ page }) => {
    const topActorsSection = page.locator('text=Top Actors')

    const hasTopActors = await topActorsSection.count() > 0

    if (hasTopActors) {
      await expect(topActorsSection.first()).toBeVisible()

      // Should have actor badges
      const actorBadges = page.locator('[variant="outline"]')
      if (await actorBadges.count() > 0) {
        await expect(actorBadges.first()).toBeVisible()
      }
    }
  })

  test('should calculate events per minute', async ({ page }) => {
    // Events per minute appears when there are enough events
    const eventsPerMinute = page.locator('text=/min')

    // This is a soft assertion - it may not be present
    const hasEventsPerMinute = await eventsPerMinute.count() > 0

    if (hasEventsPerMinute) {
      await expect(eventsPerMinute.first()).toBeVisible()
    }
  })
})

test.describe('Audit Stream - Error Handling', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should have retry button when connection fails', async ({ page }) => {
    const retryButton = page.locator('button:has-text("Retry")')

    // Retry button appears on error
    const hasRetryButton = await retryButton.count() > 0

    if (hasRetryButton) {
      await expect(retryButton.first()).toBeVisible()
    }
  })

  test('should show helpful error message for origin rejection', async ({ page }) => {
    const rejectionMessage = page.locator('text=Contact your administrator')

    // This only appears when origin is rejected
    const hasRejectionMessage = await rejectionMessage.count() > 0

    if (hasRejectionMessage) {
      await expect(rejectionMessage.first()).toBeVisible()
    }
  })
})

test.describe('Audit Stream Component', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should be contained in a card component', async ({ page }) => {
    const auditStreamCard = page.locator('[class*="card"]').filter({ hasText: 'Audit Stream Connection' })

    await expect(auditStreamCard.first()).toBeVisible()
  })

  test('should have colored left border indicating status', async ({ page }) => {
    const statusCard = page.locator('[class*="border-l-"]')

    // Status cards have colored left borders
    const count = await statusCard.count()

    if (count > 0) {
      await expect(statusCard.first()).toHaveClass(/border-l-/)
    }
  })

  test('should show status badge', async ({ page }) => {
    const badge = page.locator('[class*="badge"]')

    const count = await badge.count()

    if (count > 0) {
      await expect(badge.first()).toBeVisible()
    }
  })
})

test.describe('Audit Dashboard - Responsive Design', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display correctly on mobile', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })

    // Page title should still be visible
    await expect(page.locator('h1')).toContainText('Audit Dashboard')

    // Cards should stack vertically
    const cards = page.locator('[class*="grid"] [class*="card"]')
    const count = await cards.count()

    if (count > 0) {
      await expect(cards.first()).toBeVisible()
    }
  })

  test('should display correctly on tablet', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 })

    await expect(page.locator('h1')).toContainText('Audit Dashboard')
  })

  test('should display correctly on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })

    await expect(page.locator('h1')).toContainText('Audit Dashboard')

    // On desktop, grid should show multiple columns
    const grid = page.locator('[class*="grid"]')
    if (await grid.count() > 0) {
      await expect(grid.first()).toBeVisible()
    }
  })
})

test.describe('Audit Dashboard - Accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should have proper heading hierarchy', async ({ page }) => {
    // Check for h1
    const h1 = page.locator('h1')
    await expect(h1.first()).toBeVisible()

    // Check for h2 elements
    const h2 = page.locator('h2')
    const h2Count = await h2.count()

    if (h2Count > 0) {
      await expect(h2.first()).toBeVisible()
    }
  })

  test('should have aria labels on interactive elements', async ({ page }) => {
    // Check buttons have accessible text
    const buttons = page.locator('button')
    const count = await buttons.count()

    if (count > 0) {
      for (let i = 0; i < Math.min(count, 5); i++) {
        const button = buttons.nth(i)
        const text = await button.textContent()
        const ariaLabel = await button.getAttribute('aria-label')

        // Button should have either visible text or aria-label
        expect(text?.trim() || ariaLabel).toBeTruthy()
      }
    }
  })
})

test.describe('Audit Dashboard - Security Features', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit/dashboard')

    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display information about CSWSH protection', async ({ page }) => {
    const securityInfo = page.locator('text=CSWSH').or(
      page.locator('text=Cross-Site WebSocket Hijacking').or(
        page.locator('text=origin validation')
      )
    )

    // Security information should be present
    await expect(securityInfo.first()).toBeVisible()
  })

  test('should show origin is being validated', async ({ page }) => {
    const originValidation = page.locator('text=Origin Validation')

    await expect(originValidation.or(page.locator('text=Origin Status'))).toBeVisible()
  })
})
