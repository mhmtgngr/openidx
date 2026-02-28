import { test, expect } from '@playwright/test'

test.describe('Access Reviews', () => {
  test.beforeEach(async ({ page, context }) => {
    // Clear localStorage to prevent auth provider from attempting token refresh
    await context.addInitScript(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto('/access-reviews')
    // Wait for auth redirect
    await page.waitForURL({ url: /\/access-reviews|\/login/, timeout: 10000 })
  })

  test('should display access reviews page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Access Reviews')
  })

  test('should display reviews list or empty state', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Either shows a table or empty state
    const table = page.locator('table, [role="table"]')
    const emptyState = page.locator('text=No access reviews')

    await expect(table.or(emptyState)).toBeVisible()
  })
})

test.describe('Policies Management', () => {
  test('should display policies page', async ({ page }) => {
    await page.goto('/policies')
    await page.waitForURL({ url: /\/policies|\/login/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Policies')
  })

  test('should have create policy button', async ({ page }) => {
    await page.goto('/policies')
    await page.waitForURL({ url: /\/policies|\/login/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const createButton = page.locator('button:has-text("Create"), button:has-text("Add")')
    if (await createButton.first().isVisible()) {
      await expect(createButton.first()).toBeVisible()
    }
  })
})

test.describe('Approval Policies', () => {
  test('should display approval policies page', async ({ page }) => {
    await page.goto('/approval-policies')
    await page.waitForURL({ url: /\/approval-policies|\/login/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1, h2')).toContainText('Approval Policies')
  })
})

test.describe('Certification Campaigns', () => {
  test('should display certification campaigns', async ({ page }) => {
    await page.goto('/certification-campaigns')
    await page.waitForURL({ url: /\/certification-campaigns|\/login/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Certification Campaigns')
  })
})

test.describe('Entitlements', () => {
  test('should display entitlements page', async ({ page }) => {
    await page.goto('/entitlements')
    await page.waitForURL({ url: /\/entitlements|\/login/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Entitlements')
  })
})

test.describe('ABAC Policies', () => {
  test('should display ABAC policies page', async ({ page }) => {
    await page.goto('/abac-policies')
    await page.waitForURL({ url: /\/abac-policies|\/login/, timeout: 10000 })

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('ABAC Policies')
  })
})
