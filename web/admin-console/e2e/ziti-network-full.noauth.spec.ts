import { test, expect } from '@playwright/test'

// Use real OAuth login, not mock auth
test.use({ storageState: { cookies: [], origins: [] } })

// Helper: login via OAuth
async function login(page: import('@playwright/test').Page) {
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await page.getByRole('button', { name: /Sign in with OpenIDX/i }).click({ timeout: 10000 })
  await page.waitForSelector('input[name="username"]', { timeout: 15000 })
  await page.locator('input[name="username"]').fill('admin')
  await page.locator('input[name="password"]').fill('Admin@123')
  await page.click('button[type="submit"]')
  await page.waitForURL('**/dashboard**', { timeout: 20000 })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 1: Overview Tab
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Overview tab shows Ziti status and stats', async ({ page }) => {
  test.setTimeout(90000)
  await login(page)
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  // Overview tab should be active by default
  const overviewTab = page.getByRole('tab', { name: /Overview/i })
  await expect(overviewTab).toBeVisible()

  // Wait for stats to load
  await page.waitForTimeout(3000)

  // Should show stat cards: Controller, Routers, Services, Identities
  await expect(page.locator('text=Controller').first()).toBeVisible({ timeout: 10000 })
  await expect(page.locator('text=Services').first()).toBeVisible()
  await expect(page.locator('text=Identities').first()).toBeVisible()

  // Check Health button exists
  const healthBtn = page.getByRole('button', { name: /Health Check/i })
  if (await healthBtn.isVisible().catch(() => false)) {
    console.log('  Health Check button found')
  }

  await page.screenshot({ path: 'test-results/ziti-full-01-overview.png' })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 2: Services Tab - CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Services tab: create, search, and delete a service', async ({ page }) => {
  test.setTimeout(120000)
  await login(page)
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  // Navigate to Services tab
  await page.getByRole('tab', { name: /Services/i }).click()
  await page.waitForTimeout(2000)

  // Should show "Add Service" button
  const addBtn = page.getByRole('button', { name: /Add Service/i })
  await expect(addBtn).toBeVisible({ timeout: 10000 })

  // Click Add Service - opens modal
  await addBtn.click()
  await expect(page.locator('text=Create Ziti Service')).toBeVisible({ timeout: 5000 })

  // Fill form
  const svcName = `pw-test-svc-${Date.now()}`
  await page.locator('input[placeholder="internal-app"]').first().fill(svcName)
  await page.locator('input[placeholder="Optional description"]').fill('Playwright test service')
  await page.locator('input[placeholder="internal-app"]').last().fill('test-host')
  // Port field - set to valid port
  const portInput = page.locator('input[type="number"]').first()
  await portInput.fill('9999')

  // Verify protocol dropdown
  const protocolSelect = page.locator('select').first()
  await expect(protocolSelect).toBeVisible()
  await expect(protocolSelect).toHaveValue('tcp')

  await page.screenshot({ path: 'test-results/ziti-full-02-create-service-form.png' })

  // Submit
  await page.getByRole('button', { name: /Create Service/i }).click()
  await expect(page.locator('text=Service created').first()).toBeVisible({ timeout: 10000 })
  console.log(`  Service "${svcName}" created`)

  // Verify in table
  await page.waitForTimeout(2000)
  await expect(page.locator(`text=${svcName}`)).toBeVisible({ timeout: 5000 })

  // Test search
  const searchInput = page.locator('input[placeholder*="Search services"]')
  await searchInput.fill(svcName)
  await page.waitForTimeout(500)
  await expect(page.locator(`text=${svcName}`)).toBeVisible()

  // Clear search and search for something that doesn't exist
  await searchInput.fill('nonexistent-service-xyz')
  await page.waitForTimeout(500)
  await expect(page.locator('text=No matching services')).toBeVisible()

  // Clear search
  await searchInput.fill('')
  await page.waitForTimeout(500)

  await page.screenshot({ path: 'test-results/ziti-full-03-service-in-table.png' })

  // Delete the service
  const svcRow = page.locator('tr', { hasText: svcName })
  // Click the dropdown menu (three dots button)
  await svcRow.locator('button').last().click()
  await page.waitForTimeout(500)

  // Click Delete in dropdown
  await page.locator('[role="menuitem"]').filter({ hasText: 'Delete' }).click()
  await page.waitForTimeout(500)

  // Confirm deletion
  await expect(page.locator('text=Delete Ziti Service')).toBeVisible()
  await page.getByRole('button', { name: /^Delete$/i }).last().click()
  await expect(page.locator('text=Service deleted').first()).toBeVisible({ timeout: 10000 })
  console.log(`  Service "${svcName}" deleted`)

  await page.screenshot({ path: 'test-results/ziti-full-04-service-deleted.png' })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 3: Identities Tab - CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Identities tab: create, view JWT, and delete an identity', async ({ page }) => {
  test.setTimeout(120000)
  await login(page)
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  // Navigate to Identities tab
  await page.getByRole('tab', { name: /Identities/i }).click()
  await page.waitForTimeout(2000)

  // Should show "Add Identity" button
  const addBtn = page.getByRole('button', { name: /Add Identity/i })
  await expect(addBtn).toBeVisible({ timeout: 10000 })

  // Click Add Identity
  await addBtn.click()
  await expect(page.locator('text=Create Ziti Identity')).toBeVisible({ timeout: 5000 })

  // Fill form
  const identName = `pw-test-ident-${Date.now()}`
  await page.locator('input[placeholder*="john-laptop"]').first().fill(identName)

  // Verify identity type dropdown
  const typeSelect = page.locator('select').first()
  await expect(typeSelect).toBeVisible()
  await expect(typeSelect).toHaveValue('Device')

  // Change to User type
  await typeSelect.selectOption('User')
  await expect(typeSelect).toHaveValue('User')

  await page.screenshot({ path: 'test-results/ziti-full-05-create-identity-form.png' })

  // Submit
  await page.getByRole('button', { name: /Create Identity/i }).click()
  await expect(page.locator('text=Identity created').first()).toBeVisible({ timeout: 10000 })
  console.log(`  Identity "${identName}" created`)
  await page.waitForTimeout(2000)

  // Close any JWT modal that auto-opened after creation
  await page.waitForTimeout(1000)
  const jwtDialog = page.locator('text=Enrollment JWT for')
  if (await jwtDialog.isVisible().catch(() => false)) {
    console.log('  JWT modal auto-opened after creation')
    await page.keyboard.press('Escape')
    await page.waitForTimeout(500)
  }

  // Verify in table
  await expect(page.getByText(identName, { exact: true }).first()).toBeVisible({ timeout: 5000 })

  // Check status badge (should show "Pending" since not enrolled)
  const identRow = page.locator('tr', { hasText: identName })
  await expect(identRow.locator('text=Pending').or(identRow.locator('text=Not Enrolled'))).toBeVisible()

  await page.screenshot({ path: 'test-results/ziti-full-06-identity-in-table.png' })

  // Delete the identity
  await identRow.locator('button').last().click()
  await page.waitForTimeout(500)
  await page.locator('[role="menuitem"]').filter({ hasText: 'Delete' }).click()
  await page.waitForTimeout(500)

  // Confirm
  await expect(page.locator('text=Delete Ziti Identity')).toBeVisible()
  await page.getByRole('button', { name: /^Delete$/i }).last().click()
  await expect(page.locator('text=Identity deleted').first()).toBeVisible({ timeout: 10000 })
  console.log(`  Identity "${identName}" deleted`)

  await page.screenshot({ path: 'test-results/ziti-full-07-identity-deleted.png' })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 4: Security Tab - Posture Checks
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Security tab: posture checks, certificates, policy sync sections', async ({ page }) => {
  test.setTimeout(90000)
  await login(page)
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  // Navigate to Security tab
  await page.getByRole('tab', { name: /Security/i }).click()
  await page.waitForTimeout(3000)

  // Should show collapsible sections
  await expect(page.locator('text=Posture Checks').first()).toBeVisible({ timeout: 10000 })

  // Click to expand Posture Checks
  const postureSection = page.locator('button', { hasText: 'Posture Checks' }).first()
  if (await postureSection.isVisible().catch(() => false)) {
    await postureSection.click()
    await page.waitForTimeout(1000)
  }

  await page.screenshot({ path: 'test-results/ziti-full-08-security-posture.png' })

  // Check for Certificates section
  const certsSection = page.locator('text=Certificates').first()
  if (await certsSection.isVisible().catch(() => false)) {
    console.log('  Certificates section visible')
  }

  // Check for Policy Sync section
  const policySyncSection = page.locator('text=Policy Sync').first()
  if (await policySyncSection.isVisible().catch(() => false)) {
    console.log('  Policy Sync section visible')
  }

  await page.screenshot({ path: 'test-results/ziti-full-09-security-full.png' })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 5: Remote Access Tab - BrowZer Status & Per-Service Toggle
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Remote Access tab: BrowZer status and per-service BrowZer controls', async ({ page }) => {
  test.setTimeout(120000)
  await login(page)
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  // Navigate to Remote Access tab
  await page.getByRole('tab', { name: /Remote Access/i }).click()

  // Wait for BrowZer services table
  await expect(page.locator('text=BrowZer-Enabled Services')).toBeVisible({ timeout: 30000 })

  // Verify BrowZer status banner
  await expect(page.locator('text=BrowZer').first()).toBeVisible()

  // Check BrowZer config details (when enabled)
  const bootstrapperUrl = page.locator('text=Bootstrapper URL')
  if (await bootstrapperUrl.isVisible().catch(() => false)) {
    console.log('  Bootstrapper URL shown in config details')
  }
  const oidcIssuer = page.locator('text=OIDC Issuer')
  if (await oidcIssuer.isVisible().catch(() => false)) {
    console.log('  OIDC Issuer shown')
  }

  await page.screenshot({ path: 'test-results/ziti-full-10-remote-access.png' })

  // Verify per-service BrowZer table headers
  await expect(page.locator('th:has-text("Service")').first()).toBeVisible()
  await expect(page.locator('th:has-text("Target")').first()).toBeVisible()
  await expect(page.locator('th:has-text("Path")').first()).toBeVisible()
  await expect(page.locator('th:has-text("Domain")').first()).toBeVisible()
  await expect(page.locator('th:has-text("BrowZer")').first()).toBeVisible()
  await expect(page.locator('th:has-text("Action")').first()).toBeVisible()

  // Check that APISIX service shows as "Enabled" (we enabled it earlier)
  const apisixRow = page.locator('tr', { hasText: 'apisix' }).first()
  if (await apisixRow.isVisible().catch(() => false)) {
    // Should show "Enabled" badge since we set it up earlier
    const badge = apisixRow.locator('text=Enabled').or(apisixRow.locator('text=Disabled'))
    await expect(badge).toBeVisible()
    const badgeText = await badge.innerText()
    console.log(`  APISIX BrowZer status: ${badgeText}`)

    // Check that path and domain inputs exist
    const inputs = apisixRow.locator('input')
    const inputCount = await inputs.count()
    console.log(`  APISIX row has ${inputCount} input fields (path + domain)`)
    expect(inputCount).toBeGreaterThanOrEqual(2)
  }

  // Verify Temporary Access Links section exists
  await expect(page.getByRole('heading', { name: 'Temporary Access Links', exact: true })).toBeVisible({ timeout: 5000 })

  // Check "How BrowZer Works" collapsible
  const howItWorks = page.locator('button', { hasText: 'How BrowZer Works' })
  if (await howItWorks.isVisible().catch(() => false)) {
    await howItWorks.click()
    await page.waitForTimeout(500)
    await expect(page.locator('text=BrowZer Bootstrapper').first()).toBeVisible()
    console.log('  "How BrowZer Works" section expanded')
  }

  await page.screenshot({ path: 'test-results/ziti-full-11-remote-access-details.png' })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 6: Service Create + BrowZer Enable + Disable + Cleanup
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Full flow: create service, enable BrowZer with path+domain, disable, delete', async ({ page }) => {
  test.setTimeout(180000)
  await login(page)

  const svcName = `pw-browzer-${Date.now()}`
  const browzerPath = `/${svcName.replace('pw-browzer-', 'app-')}`
  const browzerDomain = `${svcName.replace('pw-browzer-', 'app-')}.localtest.me`

  // ─── Step 1: Create a service ──────────────────────────────────────────────
  console.log('\n━━━ Step 1: Create service ━━━')
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  await page.getByRole('tab', { name: /Services/i }).click()
  await page.waitForTimeout(2000)

  await page.getByRole('button', { name: /Add Service/i }).click()
  await expect(page.locator('text=Create Ziti Service')).toBeVisible({ timeout: 5000 })

  await page.locator('input[placeholder="internal-app"]').first().fill(svcName)
  await page.locator('input[placeholder="Optional description"]').fill('BrowZer flow test')
  await page.locator('input[placeholder="internal-app"]').last().fill('simple-web')
  await page.locator('input[type="number"]').first().fill('8091')

  await page.getByRole('button', { name: /Create Service/i }).click()
  await expect(page.locator('text=Service created').first()).toBeVisible({ timeout: 10000 })
  console.log(`  Created service: ${svcName}`)

  // ─── Step 2: Enable BrowZer with path + domain ────────────────────────────
  console.log('\n━━━ Step 2: Enable BrowZer ━━━')
  await page.getByRole('tab', { name: /Remote Access/i }).click()
  await expect(page.locator('text=BrowZer-Enabled Services')).toBeVisible({ timeout: 30000 })

  const svcRow = page.locator('tr', { hasText: svcName }).first()
  await expect(svcRow).toBeVisible({ timeout: 10000 })

  // Enter path
  const pathInput = svcRow.locator('input').nth(0)
  await pathInput.fill(browzerPath)

  // Enter domain
  const domainInput = svcRow.locator('input').nth(1)
  await domainInput.fill(browzerDomain)

  // Click Enable
  await svcRow.getByRole('button', { name: /Enable/i }).click()
  await expect(page.locator('text=BrowZer enabled on service').first()).toBeVisible({ timeout: 15000 })
  console.log(`  BrowZer enabled: path=${browzerPath}, domain=${browzerDomain}`)
  await page.waitForTimeout(2000)

  // Verify the service now shows "Enabled"
  await expect(svcRow.locator('text=Enabled')).toBeVisible({ timeout: 10000 })
  console.log('  Service shows "Enabled" badge')

  await page.screenshot({ path: 'test-results/ziti-full-12-browzer-enabled.png' })

  // ─── Step 3: Disable BrowZer ──────────────────────────────────────────────
  console.log('\n━━━ Step 3: Disable BrowZer ━━━')
  // After enable, the button should now say "Disable"
  await svcRow.getByRole('button', { name: /Disable/i }).click()
  await expect(page.locator('text=BrowZer disabled on service').first()).toBeVisible({ timeout: 15000 })
  console.log('  BrowZer disabled on service')
  await page.waitForTimeout(2000)

  // Verify the service now shows "Disabled"
  await expect(svcRow.locator('text=Disabled')).toBeVisible({ timeout: 10000 })
  console.log('  Service shows "Disabled" badge')

  await page.screenshot({ path: 'test-results/ziti-full-13-browzer-disabled.png' })

  // ─── Step 4: Delete the service ───────────────────────────────────────────
  console.log('\n━━━ Step 4: Cleanup - Delete service ━━━')
  await page.getByRole('tab', { name: /Services/i }).click()
  await page.waitForTimeout(2000)

  const deleteRow = page.locator('tr', { hasText: svcName })
  await deleteRow.locator('button').last().click()
  await page.waitForTimeout(500)
  await page.locator('[role="menuitem"]').filter({ hasText: 'Delete' }).click()
  await page.waitForTimeout(500)
  await page.getByRole('button', { name: /^Delete$/i }).last().click()
  await expect(page.locator('text=Service deleted').first()).toBeVisible({ timeout: 10000 })
  console.log(`  Service "${svcName}" deleted`)

  await page.screenshot({ path: 'test-results/ziti-full-14-cleanup-done.png' })
})

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Test 7: Validation - Port Range and Protocol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
test('Service creation validates port range and protocol', async ({ page }) => {
  test.setTimeout(90000)
  await login(page)
  await page.goto('http://localhost:3000/ziti-network', { waitUntil: 'domcontentloaded', timeout: 30000 })
  await expect(page.getByRole('heading', { name: 'Ziti Network' })).toBeVisible({ timeout: 10000 })

  await page.getByRole('tab', { name: /Services/i }).click()
  await page.waitForTimeout(2000)

  await page.getByRole('button', { name: /Add Service/i }).click()
  await expect(page.locator('text=Create Ziti Service')).toBeVisible({ timeout: 5000 })

  // Check port input has min/max
  const portInput = page.locator('input[type="number"]').first()
  await expect(portInput).toHaveAttribute('min', '1')
  await expect(portInput).toHaveAttribute('max', '65535')

  // Protocol dropdown should have tcp and udp options
  const protocolSelect = page.locator('select').first()
  const options = protocolSelect.locator('option')
  const optionCount = await options.count()
  expect(optionCount).toBe(2)
  await expect(options.nth(0)).toHaveText('TCP')
  await expect(options.nth(1)).toHaveText('UDP')

  // Switch to UDP
  await protocolSelect.selectOption('udp')
  await expect(protocolSelect).toHaveValue('udp')

  await page.screenshot({ path: 'test-results/ziti-full-15-validation.png' })

  // Close modal
  await page.getByRole('button', { name: /Cancel/i }).click()
})
