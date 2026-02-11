import { test, expect } from '@playwright/test'

// Use real OAuth login, not mock auth
test.use({ storageState: { cookies: [], origins: [] } })

test('enable BrowZer vhost domain on APISIX service', async ({ page }) => {
  test.setTimeout(120000)

  page.on('console', msg => {
    if (msg.type() === 'error') console.log('BROWSER ERROR:', msg.text())
  })

  // ─── Step 1: Login via OAuth ───────────────────────────────────────────────
  console.log('\n━━━ Step 1: Login via OAuth ━━━')
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })

  await page.getByRole('button', { name: /Sign in with OpenIDX/i }).click({ timeout: 10000 })
  await page.waitForSelector('input[name="username"]', { timeout: 15000 })
  console.log('  OAuth login page loaded')

  await page.locator('input[name="username"]').fill('admin')
  await page.locator('input[name="password"]').fill('Admin@123')
  await page.click('button[type="submit"]')
  await page.waitForURL('**/dashboard**', { timeout: 20000 })
  console.log('  Logged in!')

  // ─── Step 2: Navigate to Ziti Network > Remote Access ──────────────────────
  console.log('\n━━━ Step 2: Navigate to Remote Access tab ━━━')
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  await page.getByRole('tab', { name: /Remote Access/i }).click()

  // Wait for the BrowZer services table to appear (requires browzerStatus.enabled && services.length > 0)
  console.log('  Waiting for BrowZer services table...')
  await expect(page.locator('text=BrowZer-Enabled Services')).toBeVisible({ timeout: 30000 })
  console.log('  BrowZer services table visible!')
  await page.screenshot({ path: 'test-results/vhost-01-remote-access.png' })

  // ─── Step 3: Find APISIX service row and enter domain ──────────────────────
  console.log('\n━━━ Step 3: Set domain on APISIX service ━━━')

  const apisixRow = page.locator('tr', { hasText: 'apisix' }).first()
  await expect(apisixRow).toBeVisible({ timeout: 10000 })
  console.log('  Found APISIX row in table')

  // If already BrowZer-enabled, disable first so inputs become editable
  const disableBtn = apisixRow.getByRole('button', { name: /Disable/i })
  if (await disableBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
    console.log('  Service already BrowZer-enabled, disabling first...')
    await disableBtn.click()
    await page.waitForTimeout(2000)
  }

  // Domain input is the second input in the row (path=first, domain=second)
  const domainInput = apisixRow.locator('input').nth(1)
  await expect(domainInput).toBeEnabled({ timeout: 5000 })
  await domainInput.click()
  await domainInput.fill('apisix.localtest.me')
  await page.waitForTimeout(1000)
  console.log('  Domain set to apisix.localtest.me')
  await page.screenshot({ path: 'test-results/vhost-02-domain-entered.png' })

  // ─── Step 4: Click Enable ──────────────────────────────────────────────────
  console.log('\n━━━ Step 4: Click Enable ━━━')
  const enableBtn = apisixRow.getByRole('button', { name: /Enable/i })
  await enableBtn.click()
  console.log('  Clicked Enable')

  // Wait for success toast
  await expect(page.locator('text=BrowZer enabled on service').first()).toBeVisible({ timeout: 15000 })
  console.log('  BrowZer enabled on APISIX with vhost domain!')
  await page.screenshot({ path: 'test-results/vhost-03-enabled.png' })
  await page.waitForTimeout(3000)

  // ─── Step 5: Final ─────────────────────────────────────────────────────────
  await page.screenshot({ path: 'test-results/vhost-04-final.png' })
  console.log('\n━━━ Done! Vhost routing enabled for apisix.localtest.me ━━━')
})
