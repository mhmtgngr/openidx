import { test, expect, Page } from '@playwright/test';

/**
 * Test that the dashboard returns role-aware data:
 * - Admin sees system-wide stats (total_users > 0)
 * - Normal user (jsmith) sees user-scoped stats (total_users = 0)
 *
 * Uses real OAuth login flow against the running services.
 */

async function loginViaOAuth(page: Page, username: string, password: string) {
  // Clear any existing auth
  await page.goto('/login');
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  await page.reload();

  // Wait for login page
  await expect(page.getByRole('heading', { name: 'OpenIDX' })).toBeVisible({ timeout: 10000 });

  // Click "Sign in with OpenIDX" to start OAuth flow
  await page.getByRole('button', { name: /sign in with openidx/i }).click();

  // Wait for OAuth service login page (dark themed with "Sign In" heading)
  await expect(page.getByRole('heading', { name: 'Sign In' })).toBeVisible({ timeout: 15000 });

  // The OAuth login form uses text labels, not <label for="..."> elements
  // Find the input fields by their position relative to the label text
  const usernameInput = page.locator('input[name="username"], input[type="text"]').first();
  const passwordInput = page.locator('input[name="password"], input[type="password"]').first();

  await expect(usernameInput).toBeVisible({ timeout: 5000 });
  await usernameInput.fill(username);
  await passwordInput.fill(password);

  // Click Sign In button
  await page.getByRole('button', { name: /sign in/i }).click();

  // Wait for redirect back to the app (dashboard or callback)
  await page.waitForURL(url => url.pathname.includes('/dashboard') || url.pathname.includes('/callback'), { timeout: 20000 });

  // If at /callback, wait for final redirect to dashboard
  if (page.url().includes('/callback')) {
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
  }
}

test.describe('Dashboard role-aware data', () => {
  // Don't use pre-loaded auth state - we do real OAuth login
  test.use({ storageState: { cookies: [], origins: [] } });

  test('admin user sees system-wide stats', async ({ page }) => {
    // Set up response listener BEFORE login (dashboard loads after redirect)
    const dashboardPromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/v1/dashboard') && resp.status() === 200,
      { timeout: 60000 }
    );

    await loginViaOAuth(page, 'admin', 'Admin@123');

    const response = await dashboardPromise;
    const data = await response.json();

    console.log('Admin dashboard data:', JSON.stringify(data, null, 2));

    // Admin should see system-wide stats
    expect(data.total_users).toBeGreaterThan(0);
    expect(data.total_users).toBe(6);

    // Verify the page renders
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 10000 });
  });

  test('normal user (jsmith) sees user-scoped stats', async ({ page }) => {
    // Set up response listener BEFORE login
    const dashboardPromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/v1/dashboard') && resp.status() === 200,
      { timeout: 60000 }
    );

    await loginViaOAuth(page, 'jsmith', 'Admin@123');

    const response = await dashboardPromise;
    const data = await response.json();

    console.log('Normal user (jsmith) dashboard data:', JSON.stringify(data, null, 2));

    // Normal user should NOT see system-wide total_users
    expect(data.total_users).toBe(0);
    expect(data.active_users).toBe(0);
    expect(data.security_alerts).toBe(0);

    // But should have user-scoped data available
    expect(data).toHaveProperty('total_groups');
    expect(data).toHaveProperty('total_applications');
    expect(data).toHaveProperty('active_sessions');

    // Verify the page renders
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 10000 });
  });
});
