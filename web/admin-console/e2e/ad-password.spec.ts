import { test, expect } from '@playwright/test';

/**
 * Active Directory Password Integration Tests
 * Tests the password-info endpoint and AD-aware password change UX
 */

test.describe('AD Password Integration', () => {
  // Mock API routes for a local user
  test.describe('Local User', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/identity/users/me', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              id: 'test-user-id',
              username: 'admin',
              email: 'admin@openidx.local',
              firstName: 'Admin',
              lastName: 'User',
              mfaEnabled: false,
              enabled: true,
            }),
          });
        }
      });

      await page.route('**/api/v1/identity/users/me/password-info', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            source: 'local',
            is_ldap: false,
            password_must_change: false,
            password_changed_at: '2026-01-15T10:00:00Z',
          }),
        });
      });

      // Mock other required endpoints
      await page.route('**/api/v1/identity/mfa/methods*', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/*/sessions', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/me/tokens', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/me/consents', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/me/trusted-browsers', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
    });

    test('should show standard password change form for local users', async ({ page }) => {
      await page.goto('/profile');
      const securityTab = page.getByRole('tab', { name: /security/i });
      await securityTab.click();

      // Should show "Change Password" heading
      await expect(page.getByRole('heading', { name: 'Change Password' })).toBeVisible();

      // Should show "Update your account password" description (not AD message)
      await expect(page.getByText('Update your account password')).toBeVisible();

      // Should NOT show AD banner
      await expect(page.getByText('Active Directory')).not.toBeVisible();

      // Should show "Change Password" button (not "Change AD Password")
      await expect(page.getByRole('button', { name: 'Change Password' })).toBeVisible();
    });

    test('should submit password change for local user', async ({ page }) => {
      let passwordChangeRequest: { currentPassword: string; newPassword: string } | null = null;

      await page.route('**/api/v1/identity/users/me/change-password', async (route) => {
        const body = route.request().postDataJSON();
        passwordChangeRequest = body;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'password changed' }),
        });
      });

      await page.goto('/profile');
      const securityTab = page.getByRole('tab', { name: /security/i });
      await securityTab.click();

      // Fill in password fields
      await page.fill('#current-password', 'OldPass123!');
      await page.fill('#new-password', 'NewPass456!');
      await page.fill('#confirm-password', 'NewPass456!');

      // Click change password
      await page.getByRole('button', { name: 'Change Password' }).click();

      // Wait for request
      await page.waitForTimeout(500);

      // Verify the API was called with correct data
      expect(passwordChangeRequest).not.toBeNull();
      expect(passwordChangeRequest!.currentPassword).toBe('OldPass123!');
      expect(passwordChangeRequest!.newPassword).toBe('NewPass456!');
    });
  });

  // Mock API routes for an LDAP/AD user
  test.describe('AD User', () => {
    test.beforeEach(async ({ page }) => {
      await page.route('**/api/v1/identity/users/me', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              id: 'ldap-user-id',
              username: 'jsmith',
              email: 'jsmith@corp.local',
              firstName: 'John',
              lastName: 'Smith',
              mfaEnabled: false,
              enabled: true,
            }),
          });
        }
      });

      await page.route('**/api/v1/identity/users/me/password-info', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            source: 'ldap',
            is_ldap: true,
            password_must_change: false,
            password_changed_at: '2026-02-10T14:30:00Z',
          }),
        });
      });

      // Mock other required endpoints
      await page.route('**/api/v1/identity/mfa/methods*', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/*/sessions', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/me/tokens', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/me/consents', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
      await page.route('**/api/v1/identity/users/me/trusted-browsers', async (route) => {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      });
    });

    test('should show AD-specific password change UI for LDAP users', async ({ page }) => {
      await page.goto('/profile');
      const securityTab = page.getByRole('tab', { name: /security/i });
      await securityTab.click();

      // Should show "Change Password" heading
      await expect(page.getByRole('heading', { name: 'Change Password' })).toBeVisible();

      // Should show AD description
      await expect(page.getByText('Your password is managed by Active Directory')).toBeVisible();

      // Should show AD banner with policy notice
      await expect(page.getByText(/Changes will be applied directly to your Active Directory account/)).toBeVisible();

      // Button should say "Change AD Password"
      await expect(page.getByRole('button', { name: 'Change AD Password' })).toBeVisible();
    });

    test('should submit password change for AD user and show success', async ({ page }) => {
      let passwordChangeRequest: { currentPassword: string; newPassword: string } | null = null;

      await page.route('**/api/v1/identity/users/me/change-password', async (route) => {
        const body = route.request().postDataJSON();
        passwordChangeRequest = body;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'password changed' }),
        });
      });

      await page.goto('/profile');
      const securityTab = page.getByRole('tab', { name: /security/i });
      await securityTab.click();

      // Fill in password fields
      await page.fill('#current-password', 'OldADPass123!');
      await page.fill('#new-password', 'NewADPass456!');
      await page.fill('#confirm-password', 'NewADPass456!');

      // Click change AD password
      await page.getByRole('button', { name: 'Change AD Password' }).click();

      // Wait for request
      await page.waitForTimeout(500);

      // Verify API was called
      expect(passwordChangeRequest).not.toBeNull();
      expect(passwordChangeRequest!.currentPassword).toBe('OldADPass123!');
      expect(passwordChangeRequest!.newPassword).toBe('NewADPass456!');
    });

    test('should show AD-specific error messages on password policy failure', async ({ page }) => {
      await page.route('**/api/v1/identity/users/me/change-password', async (route) => {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'password does not meet complexity requirements' }),
        });
      });

      await page.goto('/profile');
      const securityTab = page.getByRole('tab', { name: /security/i });
      await securityTab.click();

      await page.fill('#current-password', 'OldPass!');
      await page.fill('#new-password', 'weak');
      await page.fill('#confirm-password', 'weak');

      await page.getByRole('button', { name: 'Change AD Password' }).click();

      // Should show the AD error message in a toast
      await expect(page.getByText('password does not meet complexity requirements').first()).toBeVisible({ timeout: 5000 });
    });
  });
});
