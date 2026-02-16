import { test, expect } from '@playwright/test';

test.describe('WebAuthn MFA Login Flow', () => {
  test.beforeEach(async ({ page, context }) => {
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test('should show WebAuthn option in MFA method selection', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp', 'webauthn'],
        }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show method selection
    await expect(page.locator('text=Choose Verification Method')).toBeVisible({ timeout: 15000 });

    // Look for Security Key button with its description
    const securityKeyBtn = page.getByRole('button', { name: /Security Key/i });
    await expect(securityKeyBtn).toBeVisible();
    await expect(page.locator('text=Use your security key or biometrics')).toBeVisible();
  });

  test('should show waiting UI when WebAuthn is selected', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['webauthn'],
        }),
      });
    });

    // Mock WebAuthn begin endpoint
    await page.route('**/oauth/mfa-webauthn-begin', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          publicKey: {
            challenge: 'dGVzdC1jaGFsbGVuZ2U',
            rpId: 'localhost',
            timeout: 60000,
            allowCredentials: [],
          },
        }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // With only webauthn as method, it auto-starts
    // Should show the security key heading (use getByRole to be specific)
    await expect(page.getByRole('heading', { name: /Security Key/i })).toBeVisible({ timeout: 15000 });

    // Browser will show waiting state or error since navigator.credentials.get
    // won't work in headless mode. Either state is acceptable.
    const waitingText = page.locator('text=Waiting for your security key');
    const tryAgain = page.getByRole('button', { name: /try again/i });
    await expect(waitingText.or(tryAgain).first()).toBeVisible({ timeout: 15000 });
  });
});

test.describe('Security Keys Management Page', () => {
  test('should display security keys page', async ({ page }) => {
    // Mock the credentials API
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });

    // Use addInitScript to set auth tokens before navigation
    await page.addInitScript(() => {
      localStorage.setItem('token', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9.mock');
      localStorage.setItem('refresh_token', 'mock-refresh');
    });

    await page.goto('/security-keys');

    await expect(page.getByRole('heading', { name: /Security Keys/i }).first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Manage your WebAuthn')).toBeVisible();
    await expect(page.getByRole('button', { name: /Register Security Key/i })).toBeVisible();
  });

  test('should show registered credentials', async ({ page }) => {
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'cred-1',
            user_id: 'user-1',
            credential_id: 'abc123',
            name: 'YubiKey 5C',
            aaguid: 'test-aaguid',
            sign_count: 42,
            created_at: '2026-01-15T00:00:00Z',
            last_used_at: '2026-02-10T00:00:00Z',
          },
        ]),
      });
    });

    await page.addInitScript(() => {
      localStorage.setItem('token', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9.mock');
      localStorage.setItem('refresh_token', 'mock-refresh');
    });

    await page.goto('/security-keys');

    await expect(page.locator('text=YubiKey 5C')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Used 42 times')).toBeVisible();
  });
});
