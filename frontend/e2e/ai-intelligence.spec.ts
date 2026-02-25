import { test, expect } from '@playwright/test'

test.describe('AI Recommendations', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ai-recommendations')
  })

  test('should display AI recommendations page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Recommendations')
  })

  test('should display recommendation cards or empty state', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const recommendations = page.locator('text=Recommendation, text=No recommendations')
    await expect(recommendations.first()).toBeVisible()
  })
})

test.describe('ISPM Dashboard', () => {
  test('should display ISPM dashboard page', async ({ page }) => {
    await page.goto('/ispm')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Security Posture')
  })
})

test.describe('Predictive Analytics', () => {
  test('should display predictive analytics page', async ({ page }) => {
    await page.goto('/predictive-analytics')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Predictive Analytics')
  })
})
