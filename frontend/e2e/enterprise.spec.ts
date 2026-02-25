import { test, expect } from '@playwright/test'

test.describe('SAML Service Providers', () => {
  test('should display SAML service providers page', async ({ page }) => {
    await page.goto('/saml-service-providers')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('SAML')
  })
})

test.describe('Bulk Operations', () => {
  test('should display bulk operations page', async ({ page }) => {
    await page.goto('/bulk-operations')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Bulk Operations')
  })
})

test.describe('Email Templates', () => {
  test('should display email templates page', async ({ page }) => {
    await page.goto('/email-templates')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Email Templates')
  })
})

test.describe('Lifecycle Policies', () => {
  test('should display lifecycle policies page', async ({ page }) => {
    await page.goto('/lifecycle-policies')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Lifecycle Policies')
  })
})

test.describe('Attestation Campaigns', () => {
  test('should display attestation campaigns page', async ({ page }) => {
    await page.goto('/attestation-campaigns')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Attestation')
  })
})
