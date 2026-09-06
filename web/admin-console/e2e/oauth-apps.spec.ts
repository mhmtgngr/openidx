import { test, expect } from '@playwright/test';

test.describe('OAuth Applications Management', () => {
  test.beforeEach(async ({ page }) => {
    // The signed-in storageState from auth.setup.ts is the session. What
    // stood here overwrote it with a hand-assembled JWT ending in
    // `mock-signature`: btoa() emits standard base64, JWT requires base64url,
    // so identity-service logged "token is malformed: could not base64 decode
    // claim" on every request and the console bounced back to /login. The
    // route mocks below still stand in for the API; the SESSION has to be real.

    // Mock OAuth apps API
    await page.route('**/api/v1/oauth/applications*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'app-1',
              name: 'Demo Application',
              client_id: 'demo-app-client-id',
              redirect_uris: ['https://demo.example.com/callback'],
              grant_types: ['authorization_code', 'refresh_token'],
              scopes: ['openid', 'profile', 'email'],
              enabled: true,
              created_at: '2025-01-15T10:00:00Z',
            },
            {
              id: 'app-2',
              name: 'Mobile App',
              client_id: 'mobile-app-client-id',
              redirect_uris: ['myapp://callback'],
              grant_types: ['authorization_code'],
              scopes: ['openid', 'profile'],
              enabled: true,
              created_at: '2025-01-16T10:00:00Z',
            },
          ],
          total: 2,
          page: 1,
          per_page: 25,
        }),
      });
    });
  });

  test('should display applications page heading', async ({ page }) => {
    await page.goto('/applications');
    await expect(page.getByRole('heading', { name: /applications/i })).toBeVisible();
  });

  test('should display list of OAuth applications', async ({ page }) => {
    await page.goto('/applications');
    await expect(page.getByText('Demo Application')).toBeVisible();
    await expect(page.getByText('Mobile App')).toBeVisible();
  });

  test('should show client ID for applications', async ({ page }) => {
    await page.goto('/applications');
    await expect(page.getByText('demo-app-client-id')).toBeVisible();
  });

  test('should have create application button', async ({ page }) => {
    await page.goto('/applications');
    const createButton = page.getByRole('button', { name: /create|add|new application/i });
    await expect(createButton).toBeVisible();
  });

  test('should display application scopes', async ({ page }) => {
    await page.goto('/applications');
    await expect(page.getByText('openid')).toBeVisible();
  });
});
