import { test, expect } from '@playwright/test'

// Use real OAuth login, not mock auth
test.use({ storageState: { cookies: [], origins: [] } })

test('create service, set BrowZer path, enable, and connect', async ({ page }) => {
  test.setTimeout(180000)

  // Enable console logging for debugging
  page.on('console', msg => {
    if (msg.type() === 'error') console.log('BROWSER ERROR:', msg.text())
  })

  const SLOW = 2000 // pause between steps so you can watch

  // ─── Step 1: Login via OAuth ───────────────────────────────────────────────
  console.log('\n━━━ Step 1: Login via OAuth ━━━')
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })

  console.log('  Clicking "Sign in with OpenIDX"...')
  await page.getByRole('button', { name: /Sign in with OpenIDX/i }).click({ timeout: 10000 })

  await page.waitForSelector('input[name="username"]', { timeout: 15000 })
  console.log('  OAuth login page loaded:', page.url())
  await page.waitForTimeout(SLOW)

  // Fill in credentials slowly
  console.log('  Typing username...')
  await page.locator('input[name="username"]').click()
  await page.locator('input[name="username"]').type('admin', { delay: 80 })
  await page.waitForTimeout(500)

  console.log('  Typing password...')
  await page.locator('input[name="password"]').click()
  await page.locator('input[name="password"]').type('Admin@123', { delay: 80 })
  await page.waitForTimeout(SLOW)

  console.log('  Submitting login...')
  await page.click('button[type="submit"]')
  await page.waitForURL('**/dashboard**', { timeout: 20000 })
  console.log('  Logged in! Redirected to:', page.url())
  await page.waitForTimeout(SLOW)

  // ─── Step 2: Navigate to Ziti Network ──────────────────────────────────────
  console.log('\n━━━ Step 2: Navigate to Ziti Network ━━━')
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 15000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })
  console.log('  Ziti Network page loaded.')
  await page.waitForTimeout(SLOW)

  // ─── Step 3: Go to Services tab and create a service ───────────────────────
  console.log('\n━━━ Step 3: Create a new Ziti Service ━━━')
  await page.getByRole('tab', { name: /Services/i }).click()
  await page.waitForTimeout(SLOW)

  console.log('  Clicking "Add Service"...')
  await page.getByRole('button', { name: /Add Service/i }).click()
  await expect(page.locator('text=Create Ziti Service')).toBeVisible({ timeout: 5000 })
  await page.waitForTimeout(1000)

  // Fill in service details slowly
  const serviceName = `test-browzer-svc-${Date.now()}`
  const browzerPath = `/${serviceName.replace('test-browzer-svc-', 'app-')}`

  console.log(`  Service name: ${serviceName}`)
  console.log(`  BrowZer path: ${browzerPath}`)
  console.log(`  Target: simple-web:8091`)

  console.log('  Filling service name...')
  await page.locator('input[placeholder="internal-app"]').first().click()
  await page.locator('input[placeholder="internal-app"]').first().type(serviceName, { delay: 40 })
  await page.waitForTimeout(800)

  console.log('  Filling description...')
  await page.locator('input[placeholder="Optional description"]').click()
  await page.locator('input[placeholder="Optional description"]').type('Test BrowZer service created by Playwright', { delay: 30 })
  await page.waitForTimeout(800)

  console.log('  Filling host: simple-web...')
  const hostInput = page.locator('input[placeholder="internal-app"]').last()
  await hostInput.click()
  await hostInput.type('simple-web', { delay: 60 })
  await page.waitForTimeout(800)

  console.log('  Filling port: 8091...')
  const portInput = page.locator('input[type="number"]').first()
  await portInput.click()
  await portInput.fill('8091')
  await page.waitForTimeout(SLOW)

  await page.screenshot({ path: 'test-results/browzer-flow-01-create-form.png' })

  console.log('  Submitting service creation...')
  await page.getByRole('button', { name: /Create Service/i }).click()
  await expect(page.locator('text=Service created').first()).toBeVisible({ timeout: 10000 })
  console.log('  Service created!')
  await page.waitForTimeout(SLOW)

  // Verify in table
  await expect(page.locator(`text=${serviceName}`)).toBeVisible({ timeout: 5000 })
  console.log('  Service visible in table.')
  await page.screenshot({ path: 'test-results/browzer-flow-02-service-created.png' })
  await page.waitForTimeout(SLOW)

  // ─── Step 4: Go to Remote Access tab ───────────────────────────────────────
  console.log('\n━━━ Step 4: Navigate to Remote Access tab ━━━')
  await page.getByRole('tab', { name: /Remote Access/i }).click()
  await page.waitForTimeout(SLOW)

  const browzerEnabled = await page.locator('text=Enabled').first().isVisible().catch(() => false)
  console.log('  BrowZer status:', browzerEnabled ? 'Enabled' : 'Disabled')
  await page.screenshot({ path: 'test-results/browzer-flow-03-remote-access.png' })
  await page.waitForTimeout(SLOW)

  // ─── Step 5: Find service in BrowZer table and set path ────────────────────
  console.log('\n━━━ Step 5: Set BrowZer path and enable ━━━')
  const serviceRow = page.locator('tr', { hasText: serviceName })

  if (await serviceRow.isVisible({ timeout: 5000 }).catch(() => false)) {
    console.log('  Found service in BrowZer services table.')
    await page.waitForTimeout(1000)

    // Check if already BrowZer-enabled (from a previous test run leftover)
    const disableBtn = serviceRow.getByRole('button', { name: /Disable/i })
    if (await disableBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      console.log('  Service already BrowZer-enabled, disabling first...')
      await disableBtn.click()
      await page.waitForTimeout(SLOW)
    }

    // Use the path input (first input, w-32 class) — target by placeholder pattern
    console.log(`  Typing BrowZer path: ${browzerPath}`)
    const pathInput = serviceRow.locator('input').first()
    await expect(pathInput).toBeEnabled({ timeout: 5000 })
    await pathInput.click()
    await pathInput.type(browzerPath, { delay: 60 })
    await page.waitForTimeout(SLOW)

    await page.screenshot({ path: 'test-results/browzer-flow-04-path-entered.png' })

    // Click Enable
    console.log('  Clicking "Enable" on service...')
    const enableBtn = serviceRow.getByRole('button', { name: /Enable/i })
    await enableBtn.click()
    await page.waitForTimeout(SLOW)

    // Wait for success toast
    await expect(page.locator('text=BrowZer enabled on service').first()).toBeVisible({ timeout: 10000 })
    console.log('  BrowZer enabled on service with path!')
    await page.screenshot({ path: 'test-results/browzer-flow-05-browzer-enabled.png' })
    await page.waitForTimeout(SLOW)
  } else {
    console.log('  WARNING: Service not visible in BrowZer table.')
    await page.screenshot({ path: 'test-results/browzer-flow-05-service-not-found.png' })
  }

  // ─── Step 6: Check BrowZer bootstrapper URL ────────────────────────────────
  console.log('\n━━━ Step 6: Check BrowZer URLs ━━━')
  const bootstrapperLink = page.locator('a:has-text("Open Bootstrapper")')
  if (await bootstrapperLink.isVisible().catch(() => false)) {
    const href = await bootstrapperLink.getAttribute('href')
    console.log(`  Bootstrapper URL: ${href}`)
    console.log(`  Full BrowZer path URL: ${href}${browzerPath}`)
  }
  await page.waitForTimeout(SLOW)

  // ─── Step 7: Try Connect button ────────────────────────────────────────────
  console.log('\n━━━ Step 7: Try Connect button ━━━')
  const connectBtn = page.getByRole('button', { name: /Connect/i }).first()
  if (await connectBtn.isVisible().catch(() => false)) {
    console.log('  Connect button found - clicking...')
    await connectBtn.click()
    await page.waitForTimeout(3000)
    await page.screenshot({ path: 'test-results/browzer-flow-06-connect.png' })
  } else {
    console.log('  No Connect button visible.')
  }
  await page.waitForTimeout(SLOW)

  // Final screenshot
  await page.screenshot({ path: 'test-results/browzer-flow-07-final.png' })
  console.log('\n━━━ Test complete! ━━━')
  await page.waitForTimeout(SLOW)

  // ─── Cleanup: Delete the test service ──────────────────────────────────────
  console.log('\n━━━ Cleanup: Deleting test service ━━━')
  await page.getByRole('tab', { name: /Services/i }).click()
  await page.waitForTimeout(SLOW)

  const svcRow = page.locator('tr', { hasText: serviceName })
  if (await svcRow.isVisible().catch(() => false)) {
    await svcRow.getByRole('button').filter({ has: page.locator('svg') }).last().click()
    await page.waitForTimeout(1000)

    await page.locator('text=Delete').click()
    await page.waitForTimeout(1000)

    const confirmBtn = page.getByRole('button', { name: /Delete/i }).last()
    if (await confirmBtn.isVisible()) {
      await confirmBtn.click()
      await expect(page.locator('text=Service deleted').first()).toBeVisible({ timeout: 5000 })
      console.log('  Test service cleaned up.')
    }
  }
  await page.waitForTimeout(1000)
})
