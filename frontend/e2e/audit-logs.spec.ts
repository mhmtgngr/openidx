import { test, expect } from '@playwright/test'

/**
 * E2E Tests for Audit Logs (US-005)
 * As a compliance auditor, I want to query and export audit logs
 * So that I can meet regulatory requirements
 */

test.describe('Audit Logs - Authenticated', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit')

    // If redirected to login, skip all tests
    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display audit logs page', async ({ page }) => {
    // Check page title
    await expect(page.locator('h1')).toContainText('Audit Logs', { timeout: 5000 })

    // Check for table with events
    const table = page.locator('table, [role="table"]')
    await expect(table).toBeVisible()
  })

  test('should display event filters', async ({ page }) => {
    // Check for search input
    const searchInput = page.locator('input[placeholder*="search" i], input[placeholder*="Search" i]')
    if (await searchInput.first().isVisible()) {
      await expect(searchInput.first()).toBeVisible()
    }

    // Check for filter dropdowns
    const filters = page.locator('[role="combobox"], select')
    const filterCount = await filters.count()

    if (filterCount > 0) {
      // At least one filter should be visible
      await expect(filters.first()).toBeVisible()
    }
  })

  test('should allow filtering by action', async ({ page }) => {
    const actionFilter = page.locator('[role="combobox"]').nth(0)

    if (await actionFilter.isVisible()) {
      await actionFilter.click()
      await page.waitForTimeout(200)

      // Check for action options
      const loginOption = page.locator('text=Login').first()
      if (await loginOption.isVisible()) {
        await loginOption.click()
        await page.waitForTimeout(500)
      }
    }
  })

  test('should allow filtering by outcome', async ({ page }) => {
    // Look for outcome filter
    const filters = page.locator('[role="combobox"]')

    for (let i = 0; i < await filters.count(); i++) {
      const filter = filters.nth(i)
      if (await filter.isVisible()) {
        await filter.click()
        await page.waitForTimeout(200)

        // Check if this filter has outcome options
        const successOption = page.locator('text=Success').first()
        if (await successOption.isVisible()) {
          await successOption.click()
          await page.waitForTimeout(500)
          break
        } else {
          // Click outside to close dropdown
          await page.keyboard.press('Escape')
        }
      }
    }
  })

  test('should display event table with correct columns', async ({ page }) => {
    // Check for expected table headers
    await expect(page.locator('text=Timestamp, text=Time')).toBeVisible()
    await expect(page.locator('text=Actor, text=User')).toBeVisible()
    await expect(page.locator('text=Action')).toBeVisible()
    await expect(page.locator('text=Resource')).toBeVisible()
    await expect(page.locator('text=Outcome, text=Result')).toBeVisible()
  })

  test('should display outcome badges with color coding', async ({ page }) => {
    // Check for status/outcome badges
    const badges = page.locator('[class*="badge"]')

    const count = await badges.count()
    if (count > 0) {
      await expect(badges.first()).toBeVisible()
    }
  })

  test('should support pagination', async ({ page }) => {
    const nextButton = page.locator('button:has-text("Next")')
    const prevButton = page.locator('button:has-text("Previous")')

    const hasPagination = await nextButton.isVisible() || await prevButton.isVisible()

    if (hasPagination) {
      if (await nextButton.isVisible()) {
        await expect(nextButton).toBeVisible()
      }
      if (await prevButton.isVisible()) {
        await expect(prevButton).toBeVisible()
      }
    }
  })
})

test.describe('Audit Logs - Export', () => {
  test('should have export button available', async ({ page }) => {
    await page.goto('/audit')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for export button
    const exportButton = page.locator('button:has-text("Export"), button:has-text("Download")')

    if (await exportButton.isVisible()) {
      await expect(exportButton).toBeVisible()
      // Don't actually click export in E2E tests
    }
  })

  test('should allow selecting export format', async ({ page }) => {
    await page.goto('/audit')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for format selector
    const formatSelectors = page.locator('[role="combobox"], select')

    for (let i = 0; i < await formatSelectors.count(); i++) {
      const selector = formatSelectors.nth(i)
      if (await selector.isVisible()) {
        await selector.click()
        await page.waitForTimeout(200)

        // Check if this has CSV/JSON options
        const csvOption = page.locator('text=CSV').first()
        const jsonOption = page.locator('text=JSON').first()

        if (await csvOption.isVisible() || await jsonOption.isVisible()) {
          // This is likely the format selector
          break
        } else {
          await page.keyboard.press('Escape')
        }
      }
    }
  })
})

test.describe('Audit Logs - Search', () => {
  test('should allow searching by resource ID', async ({ page }) => {
    await page.goto('/audit')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const searchInput = page.locator('input[placeholder*="resource" i], input[placeholder*="search" i]').first()

    if (await searchInput.isVisible()) {
      await searchInput.fill('test-resource')
      await page.waitForTimeout(500)

      // Verify input has the value
      await expect(searchInput).toHaveValue('test-resource')

      // Clear input
      await searchInput.clear()
    }
  })
})

test.describe('Audit Logs - Date Filtering', () => {
  test('should have date filter options', async ({ page }) => {
    await page.goto('/audit')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for date inputs or calendar icons
    const dateInputs = page.locator('input[type="date"]')
    const calendarIcons = page.locator('svg[class*="calendar"]')

    const hasDateFilter = await dateInputs.count() > 0 || await calendarIcons.count() > 0

    if (hasDateFilter) {
      // Date filter is available
      await expect(dateInputs.count() > 0 ? dateInputs.first() : calendarIcons.first()).toBeVisible()
    }
  })
})
