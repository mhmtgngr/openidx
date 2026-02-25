import { test, expect } from '@playwright/test';

test.describe('Settings Page', () => {
  test.beforeEach(async ({ page, context }) => {
    // Create a mock JWT token for testing (expires in 1 hour)
    const mockPayload = {
      sub: 'test-user-id',
      email: 'admin@openidx.local',
      name: 'Test Admin',
      roles: ['admin'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = btoa(JSON.stringify(mockPayload));
    const mockToken = `${header}.${payload}.mock-signature`;

    // Set auth token in context before navigating
    await context.addInitScript((token) => {
      localStorage.setItem('token', token);
      localStorage.setItem('refresh_token', 'mock-refresh-token');
    }, mockToken);

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
