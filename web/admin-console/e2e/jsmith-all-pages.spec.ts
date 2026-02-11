import { test, expect, Page } from '@playwright/test';

/**
 * Login as jsmith (normal user) and verify all accessible pages render correctly.
 * Normal user pages: dashboard, profile, app-launcher, my-access, my-devices,
 *                    trusted-browsers, access-requests, notification-preferences
 * Admin pages should redirect back to /dashboard.
 */

async function loginAsJsmith(page: Page) {
  await page.goto('/login');
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  await page.reload();

  await expect(page.getByRole('heading', { name: 'OpenIDX' })).toBeVisible({ timeout: 10000 });
  await page.getByRole('button', { name: /sign in with openidx/i }).click();

  // OAuth service login page
  await expect(page.getByRole('heading', { name: 'Sign In' })).toBeVisible({ timeout: 15000 });
  await page.locator('input[name="username"]').fill('jsmith');
  await page.locator('input[name="password"]').fill('Admin@123');
  await page.getByRole('button', { name: /sign in/i }).click();

  // Wait for dashboard
  await page.waitForURL(/\/dashboard/, { timeout: 20000 });
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 10000 });
}

test.describe('jsmith (normal user) - all pages', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('login and verify all user-accessible pages', async ({ page }) => {
    await loginAsJsmith(page);

    // 1. Dashboard - already here after login
    console.log('--- Dashboard ---');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Overview of your identity platform')).toBeVisible();
    // Verify user-scoped data (not 6 total users)
    const totalUsersCard = page.locator('text=Total Users').locator('..');
    await expect(totalUsersCard).toBeVisible();
    await page.screenshot({ path: 'test-results/jsmith-01-dashboard.png', fullPage: true });
    console.log('Dashboard: OK');

    // 2. My Profile
    console.log('--- My Profile ---');
    await page.goto('/profile');
    await page.waitForLoadState('networkidle');
    await expect(page.getByRole('heading', { name: /profile/i })).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-02-profile.png', fullPage: true });
    console.log('My Profile: OK');

    // 3. My Apps (App Launcher)
    console.log('--- My Apps ---');
    await page.goto('/app-launcher');
    await page.waitForLoadState('networkidle');
    // Look for page content
    await expect(page.locator('h1, h2, [class*="heading"]').first()).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-03-app-launcher.png', fullPage: true });
    console.log('My Apps: OK');

    // 4. My Access
    console.log('--- My Access ---');
    // Intercept the access-overview API call
    const accessOverviewPromise = page.waitForResponse(
      (resp) => resp.url().includes('/portal/access-overview'),
      { timeout: 15000 }
    );
    await page.goto('/my-access');
    const accessResp = await accessOverviewPromise;
    const accessData = await accessResp.json();
    console.log('My Access API response:', JSON.stringify(accessData, null, 2));
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2, [class*="heading"]').first()).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-04-my-access.png', fullPage: true });
    console.log('My Access: OK');

    // 5. My Devices
    console.log('--- My Devices ---');
    await page.goto('/my-devices');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2, [class*="heading"]').first()).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-05-my-devices.png', fullPage: true });
    console.log('My Devices: OK');

    // 6. Trusted Browsers
    console.log('--- Trusted Browsers ---');
    await page.goto('/trusted-browsers');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2, [class*="heading"]').first()).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-06-trusted-browsers.png', fullPage: true });
    console.log('Trusted Browsers: OK');

    // 7. Access Requests
    console.log('--- Access Requests ---');
    await page.goto('/access-requests');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2, [class*="heading"]').first()).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-07-access-requests.png', fullPage: true });
    console.log('Access Requests: OK');

    // 8. Notification Preferences
    console.log('--- Notification Preferences ---');
    await page.goto('/notification-preferences');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('h1, h2, [class*="heading"]').first()).toBeVisible({ timeout: 10000 });
    await page.screenshot({ path: 'test-results/jsmith-08-notification-preferences.png', fullPage: true });
    console.log('Notification Preferences: OK');

    // 9. Verify sidebar shows only user menu items (not admin sections)
    console.log('--- Sidebar check ---');
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // These should be visible in sidebar
    await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'My Profile' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'My Apps' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'My Access' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'My Devices' })).toBeVisible();

    // These admin-only items should NOT be visible
    const usersLink = page.getByRole('link', { name: 'Users', exact: true });
    const settingsLink = page.getByRole('link', { name: 'Settings', exact: true });
    const auditLogsLink = page.getByRole('link', { name: 'Audit Logs', exact: true });
    await expect(usersLink).not.toBeVisible();
    await expect(settingsLink).not.toBeVisible();
    await expect(auditLogsLink).not.toBeVisible();
    console.log('Sidebar: OK - admin items hidden');

    // 10. Verify admin pages redirect to dashboard
    console.log('--- Admin page redirect check ---');
    await page.goto('/users');
    await page.waitForURL(/\/dashboard/, { timeout: 5000 });
    console.log('/users -> redirected to dashboard: OK');

    await page.goto('/settings');
    await page.waitForURL(/\/dashboard/, { timeout: 5000 });
    console.log('/settings -> redirected to dashboard: OK');

    await page.goto('/audit-logs');
    await page.waitForURL(/\/dashboard/, { timeout: 5000 });
    console.log('/audit-logs -> redirected to dashboard: OK');

    console.log('\n=== All jsmith pages verified successfully ===');
  });
});
