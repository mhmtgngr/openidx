import { test, expect } from '@playwright/test';

test.describe('Settings Page', () => {
  test.beforeEach(async ({ page }) => {
    // The signed-in storageState from auth.setup.ts is the session. What
    // stood here overwrote it with a hand-assembled JWT ending in
    // `mock-signature`: btoa() emits standard base64, JWT requires base64url,
    // so identity-service logged "token is malformed: could not base64 decode
    // claim" on every request and the console bounced back to /login. The
    // route mocks below still stand in for the API; the SESSION has to be real.

    // Mock settings API
    await page.route('**/api/v1/settings', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            site_name: 'OpenIDX',
            site_url: 'https://openidx.example.com',
            support_email: 'support@openidx.example.com',
            mfa_required: true,
            password_min_length: 12,
            password_require_uppercase: true,
            password_require_lowercase: true,
            password_require_numbers: true,
            password_require_special: true,
            session_timeout_minutes: 60,
            max_login_attempts: 5,
            lockout_duration_minutes: 15,
          }),
        });
      }
    });

    await page.goto('/settings');
  });

  test('should display settings page heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  });

  test('should display general settings section', async ({ page }) => {
    await expect(page.getByText('General Settings')).toBeVisible();
  });

  test('should display security settings section', async ({ page }) => {
    await expect(page.getByText('Security Settings')).toBeVisible();
  });

  test('should display session settings section', async ({ page }) => {
    await expect(page.getByText('Session Settings')).toBeVisible();
  });

  test('should have save settings button', async ({ page }) => {
    const saveButton = page.getByRole('button', { name: /save settings/i });
    await expect(saveButton).toBeVisible();
  });
});
