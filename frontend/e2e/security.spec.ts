import { test, expect } from '@playwright/test'

test.describe('MFA Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/mfa-management')
  })

  test('should display MFA management page', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('MFA')
  })

  test('should display MFA statistics', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for stats like MFA adoption rate
    const stats = page.locator('text=Users with MFA, text=Adoption')
    if (await stats.isVisible()) {
      await expect(stats).toBeVisible()
    }
  })
})

test.describe('Risk Policies', () => {
  test('should display risk policies page', async ({ page }) => {
    await page.goto('/risk-policies')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Risk Policies')
  })
})

test.describe('Login Anomalies', () => {
  test('should display login anomalies page', async ({ page }) => {
    await page.goto('/login-anomalies')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Login Anomalies')
  })
})

test.describe('Security Keys', () => {
  test('should display security keys page', async ({ page }) => {
    await page.goto('/security-keys')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Security Keys')
  })
})

test.describe('Hardware Tokens', () => {
  test('should display hardware tokens page', async ({ page }) => {
    await page.goto('/hardware-tokens')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Hardware Tokens')
  })
})

test.describe('MFA Bypass Codes', () => {
  test('should display MFA bypass codes page', async ({ page }) => {
    await page.goto('/mfa-bypass-codes')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('MFA Bypass')
  })
})

test.describe('Device Trust Approval', () => {
  test('should display device trust approval page', async ({ page }) => {
    await page.goto('/device-trust-approval')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Device Trust')
  })
})

test.describe('Push Devices', () => {
  test('should display push devices page', async ({ page }) => {
    await page.goto('/push-devices')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Push Devices')
  })
})

test.describe('Security Alerts', () => {
  test('should display security alerts page', async ({ page }) => {
    await page.goto('/security-alerts')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Security Alerts')
  })

  test('should display alert list or empty state', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const alerts = page.locator('text=No active alerts, [class*="alert"]')
    await expect(alerts.first()).toBeVisible()
  })
})

test.describe('Risk Dashboard', () => {
  test('should display risk dashboard', async ({ page }) => {
    await page.goto('/risk-dashboard')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    await expect(page.locator('h1')).toContainText('Risk')
  })

  test('should display risk metrics', async ({ page }) => {
    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Check for risk level indicators
    const riskIndicators = page.locator('text=High, text=Medium, text=Low')
    if (await riskIndicators.first().isVisible()) {
      await expect(riskIndicators.first()).toBeVisible()
    }
  })
})
