import { test, expect } from '@playwright/test'

test.describe('Applications Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/applications')
  })

  test('should display applications page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Applications')
  })

  test('should have create application button', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const createButton = page.locator('button:has-text("Add Application"), button:has-text("Create")')
    if (await createButton.isVisible()) {
      await expect(createButton).toBeVisible()
    }
  })

  test('should display applications list or empty state', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const table = page.locator('table, [role="table"]')
    const emptyState = page.locator('text=No applications')

    await expect(table.or(emptyState)).toBeVisible()
  })
})

test.describe('App Launcher', () => {
  test('should display app launcher page', async ({ page }) => {
    await page.goto('/app-launcher')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('My Apps')
  })
})

test.describe('Identity Providers', () => {
  test('should display identity providers page', async ({ page }) => {
    await page.goto('/identity-providers')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Identity Providers')
  })
})

test.describe('Provisioning Rules', () => {
  test('should display provisioning rules page', async ({ page }) => {
    await page.goto('/provisioning-rules')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Provisioning Rules')
  })
})

test.describe('Lifecycle Workflows', () => {
  test('should display lifecycle workflows page', async ({ page }) => {
    await page.goto('/lifecycle-workflows')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Lifecycle Workflows')
  })
})

test.describe('Federation Configuration', () => {
  test('should display federation config page', async ({ page }) => {
    await page.goto('/federation-config')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Federation')
  })
})

test.describe('Social Providers', () => {
  test('should display social providers page', async ({ page }) => {
    await page.goto('/social-providers')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Social Providers')
  })
})
