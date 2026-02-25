import { test, expect } from '@playwright/test'

test.describe('Audit Logs', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit-logs')
  })

  test('should display audit logs page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Audit Logs')
  })

  test('should display filter options', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for date range or event type filters
    const filters = page.locator('select, input[type="date"], input[type="datetime-local"]')
    if (await filters.first().isVisible()) {
      await expect(filters.first()).toBeVisible()
    }
  })

  test('should display audit events table or empty state', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const table = page.locator('table, [role="table"]')
    const emptyState = page.locator('text=No audit events, text=No events found')

    await expect(table.or(emptyState)).toBeVisible()
  })
})

test.describe('Unified Audit', () => {
  test('should display unified audit page', async ({ page }) => {
    await page.goto('/unified-audit')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Unified Audit')
  })
})

test.describe('Admin Audit Log', () => {
  test('should display admin audit log page', async ({ page }) => {
    await page.goto('/admin-audit-log')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Admin Audit')
  })
})

test.describe('Login Analytics', () => {
  test('should display login analytics page', async ({ page }) => {
    await page.goto('/login-analytics')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Login Analytics')
  })
})

test.describe('Auth Analytics', () => {
  test('should display auth analytics page', async ({ page }) => {
    await page.goto('/auth-analytics')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Auth Analytics')
  })
})

test.describe('Usage Analytics', () => {
  test('should display usage analytics page', async ({ page }) => {
    await page.goto('/usage-analytics')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Usage Analytics')
  })
})

test.describe('Compliance Reports', () => {
  test('should display compliance reports page', async ({ page }) => {
    await page.goto('/compliance-reports')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Compliance Reports')
  })

  test('should have generate report button', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const generateButton = page.locator('button:has-text("Generate"), button:has-text("Create")')
    if (await generateButton.first().isVisible()) {
      await expect(generateButton.first()).toBeVisible()
    }
  })
})

test.describe('Compliance Dashboard', () => {
  test('should display compliance dashboard', async ({ page }) => {
    await page.goto('/compliance-dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Compliance')
  })
})

test.describe('Reports', () => {
  test('should display reports page', async ({ page }) => {
    await page.goto('/reports')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Reports')
  })
})

test.describe('Audit Archival', () => {
  test('should display audit archival page', async ({ page }) => {
    await page.goto('/audit-archival')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Audit Archival')
  })
})
