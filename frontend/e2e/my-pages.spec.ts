import { test, expect } from '@playwright/test'

test.describe('My Access', () => {
  test('should display my access page', async ({ page }) => {
    await page.goto('/my-access')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('My Access')
  })
})

test.describe('My Devices', () => {
  test('should display my devices page', async ({ page }) => {
    await page.goto('/my-devices')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('My Devices')
  })
})

test.describe('Trusted Browsers', () => {
  test('should display trusted browsers page', async ({ page }) => {
    await page.goto('/trusted-browsers')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Trusted Browsers')
  })
})

test.describe('Access Requests', () => {
  test('should display access requests page', async ({ page }) => {
    await page.goto('/access-requests')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Access Requests')
  })
})

test.describe('Notification Center', () => {
  test('should display notification center page', async ({ page }) => {
    await page.goto('/notification-center')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Notifications')
  })
})

test.describe('Notification Preferences', () => {
  test('should display notification preferences page', async ({ page }) => {
    await page.goto('/notification-preferences')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Notification Preferences')
  })
})
