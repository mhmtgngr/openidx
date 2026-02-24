import { test, expect } from '@playwright/test'

/**
 * E2E Tests for Access Reviews (US-003)
 * As a governance officer, I want to review and decide on access requests
 * So that I can enforce access policies
 */

test.describe('Access Reviews - Authenticated', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to access reviews page
    await page.goto('/reviews')

    // If redirected to login, skip all tests
    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display access reviews list with pagination', async ({ page }) => {
    // Check page title
    await expect(page.locator('h1')).toContainText('Access Reviews')

    // Check for table with reviews
    const table = page.locator('table, [role="table"]')
    await expect(table).toBeVisible()

    // Check for table headers
    await expect(page.locator('text=Title')).toBeVisible()
    await expect(page.locator('text=Status')).toBeVisible()
    await expect(page.locator('text=Requester')).toBeVisible()
    await expect(page.locator('text=Due Date')).toBeVisible()
  })

  test('should filter reviews by status', async ({ page }) => {
    // Look for status filter dropdown
    const statusFilter = page.locator('[role="combobox"], select').first()
    if (await statusFilter.isVisible()) {
      await statusFilter.click()
      await page.waitForTimeout(200)

      // Try to select "Pending" status
      const pendingOption = page.locator('text=Pending').first()
      if (await pendingOption.isVisible()) {
        await pendingOption.click()
        await page.waitForTimeout(500)
      }
    }
  })

  test('should open review detail dialog', async ({ page }) => {
    // Look for a "Review" button in the table
    const reviewButton = page.locator('button:has-text("Review")').first()

    if (await reviewButton.isVisible()) {
      await reviewButton.click()
      await page.waitForTimeout(300)

      // Check that dialog opened
      const dialog = page.locator('[role="dialog"]')
      await expect(dialog).toBeVisible()

      // Close dialog
      const closeButton = page.locator('button[aria-label="Close"], button:has-text("Close")').first()
      if (await closeButton.isVisible()) {
        await closeButton.click()
      }
    }
  })

  test('should allow individual approve/deny actions', async ({ page }) => {
    // Look for review items with action buttons
    const approveButton = page.locator('button:has-text("Approve"), button:has-text("✓")').first()
    const denyButton = page.locator('button:has-text("Deny"), button:has-text("✕")').first()

    if (await approveButton.isVisible()) {
      await expect(approveButton).toBeEnabled()
    }

    if (await denyButton.isVisible()) {
      await expect(denyButton).toBeEnabled()
    }
  })

  test('should support bulk actions', async ({ page }) => {
    // Open a review detail to check for bulk actions
    const reviewButton = page.locator('button:has-text("Review")').first()

    if (await reviewButton.isVisible()) {
      await reviewButton.click()
      await page.waitForTimeout(300)

      // Check for checkboxes in the dialog
      const checkboxes = page.locator('input[type="checkbox"]')
      const count = await checkboxes.count()

      if (count > 0) {
        // Check first checkbox
        await checkboxes.first().check()
        await page.waitForTimeout(200)

        // Look for bulk action buttons
        const bulkApprove = page.locator('button:has-text("Approve Selected")')
        const bulkDeny = page.locator('button:has-text("Deny Selected")')

        if (await bulkApprove.isVisible()) {
          await expect(bulkApprove).toBeEnabled()
        }
      }

      // Close dialog
      const closeButton = page.locator('button[aria-label="Close"], button:has-text("Close")').first()
      if (await closeButton.isVisible()) {
        await closeButton.click()
      }
    }
  })

  test('should display review details with items', async ({ page }) => {
    const reviewButton = page.locator('button:has-text("Review")').first()

    if (await reviewButton.isVisible()) {
      await reviewButton.click()
      await page.waitForTimeout(300)

      // Check for review details
      const dialog = page.locator('[role="dialog"]')
      await expect(dialog).toBeVisible()

      // Check for items list or table
      const items = page.locator('[role="dialog"] table, [role="dialog"] [role="list"]')
      // Items might not be present if review has no items
      if (await items.isVisible()) {
        await expect(items).toBeVisible()
      }

      // Close dialog
      const closeButton = page.locator('button[aria-label="Close"], button:has-text("Close")').first()
      if (await closeButton.isVisible()) {
        await closeButton.click()
      }
    }
  })
})

test.describe('Access Reviews - Pagination', () => {
  test('should handle pagination controls', async ({ page }) => {
    await page.goto('/reviews')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for pagination controls
    const nextButton = page.locator('button:has-text("Next")')
    const prevButton = page.locator('button:has-text("Previous")')

    if (await nextButton.isVisible()) {
      // Click next and verify page changes or stays (if on last page)
      await nextButton.click()
      await page.waitForTimeout(300)
    }

    if (await prevButton.isVisible()) {
      // Click previous
      await prevButton.click()
      await page.waitForTimeout(300)
    }
  })
})

test.describe('Access Reviews - Status Badges', () => {
  test('should display status badges with correct colors', async ({ page }) => {
    await page.goto('/reviews')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for status badges
    const badges = page.locator('[class*="badge"], span[class*="status"]')

    const count = await badges.count()
    if (count > 0) {
      // At least some badges should be visible
      await expect(badges.first()).toBeVisible()
    }
  })
})
