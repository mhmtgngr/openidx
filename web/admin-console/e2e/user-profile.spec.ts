import { test, expect } from '@playwright/test';

test.describe('User Profile Page', () => {
  test.beforeEach(async ({ page, context }) => {
    // Mock authentication
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

    // Mock user profile API
    await page.route('**/api/v1/identity/users/me', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'test-user-id',
          username: 'testadmin',
          email: 'admin@openidx.local',
          first_name: 'Test',
          last_name: 'Admin',
          enabled: true,
          email_verified: true,
          created_at: '2025-01-01T00:00:00Z',
          mfa_enabled: true,
          mfa_methods: ['totp', 'webauthn'],
          groups: ['admins', 'users'],
          roles: ['admin'],
        }),
      });
    });

    // Mock user sessions API
    await page.route('**/api/v1/identity/users/me/sessions', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'sess-1',
              device: 'Chrome on Windows',
              ip_address: '192.168.1.100',
              current: true,
              created_at: new Date(Date.now() - 3600000).toISOString(),
              last_active: new Date().toISOString(),
            },
            {
              id: 'sess-2',
              device: 'Safari on iPhone',
              ip_address: '192.168.1.101',
              current: false,
              created_at: new Date(Date.now() - 86400000).toISOString(),
              last_active: new Date(Date.now() - 7200000).toISOString(),
            },
          ],
          total: 2,
        }),
      });
    });
  });

  test('should display user profile page heading', async ({ page }) => {
    await page.goto('/profile');
    await expect(page.getByRole('heading', { name: /my profile|profile/i })).toBeVisible();
  });

  test('should display user information', async ({ page }) => {
    await page.goto('/profile');
    await expect(page.getByText('admin@openidx.local')).toBeVisible();
    await expect(page.getByText('Test Admin')).toBeVisible();
  });

  test('should display MFA status', async ({ page }) => {
    await page.goto('/profile');
    await expect(page.getByText(/mfa|multi-factor/i)).toBeVisible();
  });

  test('should display active sessions', async ({ page }) => {
    await page.goto('/profile');
    await expect(page.getByText(/sessions|devices/i)).toBeVisible();
    await expect(page.getByText('Chrome on Windows')).toBeVisible();
  });

  test('should have password change option', async ({ page }) => {
    await page.goto('/profile');
    const changePasswordButton = page.getByRole('button', { name: /change password/i });
    await expect(changePasswordButton).toBeVisible();
  });

  test('should have MFA setup option', async ({ page }) => {
    await page.goto('/profile');
    const mfaButton = page.getByRole('button', { name: /mfa|two-factor|authenticator/i });
    await expect(mfaButton).toBeVisible();
  });

  test('should show current session indicator', async ({ page }) => {
    await page.goto('/profile');
    await expect(page.getByText(/current|this device/i)).toBeVisible();
  });
});
