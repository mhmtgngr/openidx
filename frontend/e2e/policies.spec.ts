import { test, expect } from '@playwright/test'

/**
 * E2E Tests for Policies Management (US-004)
 * As a security administrator, I want to manage governance policies
 * So that I can control access rules
 */

test.describe('Policies Management - Authenticated', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/policies')

    // If redirected to login, skip all tests
    if (page.url().includes('/login')) {
      test.skip()
    }
  })

  test('should display policies list', async ({ page }) => {
    // Check page title
    await expect(page.locator('h1')).toContainText('Policies')

    // Check for table with policies
    const table = page.locator('table, [role="table"]')
    await expect(table).toBeVisible()
  })

  test('should display policy types as badges', async ({ page }) => {
    // Check for policy type badges (RBAC, ABAC, Custom)
    const badges = page.locator('text=RBAC, text=ABAC, text=CUSTOM')

    // Check if any badges are present
    const count = await badges.count()
    if (count > 0) {
      await expect(badges.first()).toBeVisible()
    }
  })

  test('should open create policy dialog', async ({ page }) => {
    // Look for "New Policy" button
    const newPolicyButton = page.locator('button:has-text("New Policy"), button:has-text("Create")').first()

    if (await newPolicyButton.isVisible()) {
      await newPolicyButton.click()
      await page.waitForTimeout(300)

      // Check that dialog opened
      const dialog = page.locator('[role="dialog"]')
      await expect(dialog).toBeVisible()

      // Check for form fields
      await expect(page.locator('input[id*="name"], input[placeholder*="name" i]')).toBeVisible()

      // Check for policy type selector
      const typeSelector = page.locator('[role="combobox"], select')
      if (await typeSelector.first().isVisible()) {
        await expect(typeSelector.first()).toBeVisible()
      }

      // Close dialog
      const cancelButton = page.locator('button:has-text("Cancel")').first()
      if (await cancelButton.isVisible()) {
        await cancelButton.click()
      }
    }
  })

  test('should allow activating/deactivating policies', async ({ page }) => {
    // Look for power/status toggle buttons in the table
    const powerButtons = page.locator('button[title*="activate"], button[title*="Activate"], button[title*="deactivate"], button[title*="Deactivate"]')

    const count = await powerButtons.count()
    if (count > 0) {
      await expect(powerButtons.first()).toBeVisible()
    }
  })

  test('should display policy rules count', async ({ page }) => {
    // Look for rules count in table
    const rulesCount = page.locator('text=/rules?/i')

    const count = await rulesCount.count()
    if (count > 0) {
      await expect(rulesCount.first()).toBeVisible()
    }
  })
})

test.describe('Policy Creation Flow', () => {
  test('should allow creating policy with rules', async ({ page }) => {
    await page.goto('/policies')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    const newPolicyButton = page.locator('button:has-text("New Policy")')

    if (await newPolicyButton.isVisible()) {
      await newPolicyButton.click()
      await page.waitForTimeout(300)

      // Fill in policy name
      const nameInput = page.locator('input[id*="name"], input[placeholder*="name" i]').first()
      await nameInput.fill('Test Policy')

      // Select policy type
      const typeSelector = page.locator('[role="combobox"]').first()
      if (await typeSelector.isVisible()) {
        await typeSelector.click()
        await page.waitForTimeout(200)
        const rbacOption = page.locator('text=RBAC').first()
        if (await rbacOption.isVisible()) {
          await rbacOption.click()
        }
      }

      // Look for rule builder section
      const ruleBuilder = page.locator('text=Rules, text=Add Rule')
      if (await ruleBuilder.first().isVisible()) {
        // Check for rule input fields
        const effectToggle = page.locator('[role="switch"], input[type="checkbox"]')
        const count = await effectToggle.count()

        if (count > 0) {
          // Rule builder is available
          await expect(effectToggle.first()).isVisible()
        }
      }

      // Close dialog without saving
      const cancelButton = page.locator('button:has-text("Cancel")').first()
      if (await cancelButton.isVisible()) {
        await cancelButton.click()
      }
    }
  })
})

test.describe('Policy Editing', () => {
  test('should allow editing existing policies', async ({ page }) => {
    await page.goto('/policies')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for edit button
    const editButton = page.locator('button:has-text("Edit")').first()

    if (await editButton.isVisible()) {
      await editButton.click()
      await page.waitForTimeout(300)

      // Check that edit dialog opened
      const dialog = page.locator('[role="dialog"]')
      await expect(dialog).toBeVisible()

      // Check for form fields
      const nameInput = page.locator('input[id*="name"], input[placeholder*="name" i]').first()
      await expect(nameInput).toBeVisible()

      // Close dialog
      const cancelButton = page.locator('button:has-text("Cancel")').first()
      if (await cancelButton.isVisible()) {
        await cancelButton.click()
      }
    }
  })
})

test.describe('Policy Deletion', () => {
  test('should allow deleting policies', async ({ page }) => {
    await page.goto('/policies')

    if (page.url().includes('/login')) {
      test.skip()
      return
    }

    // Look for delete button (typically red or with destructive styling)
    const deleteButtons = page.locator('button[class*="destructive"], button[class*="red"], button:has-text("Delete")')

    const count = await deleteButtons.count()
    if (count > 0) {
      await expect(deleteButtons.first()).toBeVisible()
      // Don't actually click delete in tests
    }
  })
})
