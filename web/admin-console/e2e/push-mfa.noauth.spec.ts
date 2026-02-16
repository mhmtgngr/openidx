import { test, expect } from '@playwright/test';

test.describe('Push MFA Login Flow', () => {
  test.beforeEach(async ({ page, context }) => {
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test('should show Push Notification option in MFA method selection', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp', 'push'],
        }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show method selection
    await expect(page.locator('text=Choose Verification Method')).toBeVisible({ timeout: 15000 });

    // Look for Push Notification option
    const pushBtn = page.getByRole('button', { name: /Push Notification/i });
    await expect(pushBtn).toBeVisible();
    await expect(page.locator('text=Approve on your mobile device')).toBeVisible();
  });

  test('should show challenge code when push is initiated', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['push'],
        }),
      });
    });

    await page.route('**/oauth/mfa-push-begin', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          challenge_id: 'challenge-123',
          challenge_code: '42',
          expires_at: new Date(Date.now() + 120000).toISOString(),
        }),
      });
    });

    await page.route('**/oauth/mfa-push-status/*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'pending', expires_at: new Date(Date.now() + 120000).toISOString() }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show the challenge code
    await expect(page.locator('text=42').first()).toBeVisible({ timeout: 15000 });
    await expect(page.locator('text=Waiting for approval')).toBeVisible();

    // Should have a cancel button
    await expect(page.getByRole('button', { name: /cancel/i })).toBeVisible();
  });

  test('should complete login when push is approved', async ({ page }) => {
    let pollCount = 0;

    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['push'],
        }),
      });
    });

    await page.route('**/oauth/mfa-push-begin', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          challenge_id: 'challenge-456',
          challenge_code: '73',
          expires_at: new Date(Date.now() + 120000).toISOString(),
        }),
      });
    });

    await page.route('**/oauth/mfa-push-status/*', async (route) => {
      pollCount++;
      if (pollCount >= 2) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'approved' }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ status: 'pending' }),
        });
      }
    });

    let mfaVerifyCalled = false;
    await page.route('**/oauth/mfa-verify', async (route) => {
      mfaVerifyCalled = true;
      const body = JSON.parse(route.request().postData() || '{}');
      // Verify the correct data was sent
      if (body.method === 'push' && body.code === 'challenge-456') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ redirect_url: 'http://localhost:3000/dashboard?code=test-auth-code' }),
        });
      } else {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'unexpected request' }),
        });
      }
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Wait for the challenge code
    await expect(page.locator('text=73').first()).toBeVisible({ timeout: 15000 });

    // After approval, mfa-verify should be called and redirect should happen
    // Wait for the mfa-verify request to be made
    await page.waitForRequest((req) => req.url().includes('/oauth/mfa-verify'), { timeout: 15000 });
  });

  test('should show error when push is denied', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['push'],
        }),
      });
    });

    await page.route('**/oauth/mfa-push-begin', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          challenge_id: 'challenge-789',
          challenge_code: '56',
          expires_at: new Date(Date.now() + 120000).toISOString(),
        }),
      });
    });

    // Immediately return denied
    await page.route('**/oauth/mfa-push-status/*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ status: 'denied' }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show the denial error
    await expect(page.locator('text=Push notification was denied')).toBeVisible({ timeout: 15000 });
  });
});

test.describe('Push Devices Management Page', () => {
  test('should display push devices page', async ({ page }) => {
    await page.route('**/api/v1/identity/mfa/push/devices', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });

    await page.addInitScript(() => {
      localStorage.setItem('token', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9.mock');
      localStorage.setItem('refresh_token', 'mock-refresh');
    });

    await page.goto('/push-devices');

    await expect(page.getByRole('heading', { name: /Push Notification Devices/i })).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: /Enroll Device/i })).toBeVisible();
  });

  test('should show enrolled devices', async ({ page }) => {
    await page.route('**/api/v1/identity/mfa/push/devices', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'device-1',
            user_id: 'user-1',
            device_name: 'My iPhone',
            platform: 'ios',
            device_model: 'iPhone 15 Pro',
            enabled: true,
            trusted: true,
            created_at: '2026-01-20T00:00:00Z',
            last_used_at: '2026-02-14T00:00:00Z',
          },
        ]),
      });
    });

    await page.addInitScript(() => {
      localStorage.setItem('token', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEiLCJyb2xlcyI6WyJhZG1pbiJdLCJleHAiOjk5OTk5OTk5OTl9.mock');
      localStorage.setItem('refresh_token', 'mock-refresh');
    });

    await page.goto('/push-devices');

    await expect(page.locator('text=My iPhone')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=iPhone 15 Pro')).toBeVisible();
    await expect(page.locator('text=iOS')).toBeVisible();
    await expect(page.locator('text=Trusted').first()).toBeVisible();
  });
});
