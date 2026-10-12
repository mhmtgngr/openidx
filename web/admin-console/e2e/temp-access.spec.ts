import { test, expect } from '@playwright/test';

// Temporary access links are retired: the console lists the links issued
// before, read-only, and offers no way to create, share or open one.
test.describe('Temporary Access Links (retired)', () => {
  test.beforeEach(async ({ page }) => {
    // Mock Ziti status
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true }),
      });
    });

    // Mock BrowZer status (required for RemoteAccessTab)
    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.localtest.me/',
        }),
      });
    });

    // Mock Guacamole connections (required for RemoteAccessTab)
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ connections: [] }),
      });
    });

    // Mock Ziti services
    await page.route('**/api/v1/access/ziti/services*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ services: [] }),
      });
    });

    await page.route('**/api/v1/access/temp-access', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          links: [
            {
              id: 'link-1',
              token: 'abc12345...',
              name: 'Support Access - Server 1',
              protocol: 'ssh',
              target_host: '10.0.0.10',
              target_port: 22,
              created_by_email: 'admin@openidx.local',
              expires_at: '2024-01-15T12:00:00Z',
              max_uses: 5,
              current_uses: 2,
              status: 'expired',
              access_url: 'https://browzer.localtest.me/temp-access/abc12345...',
              created_at: '2024-01-15T10:00:00Z',
            },
          ],
        }),
      });
    });
  });

  test('lists the history read-only and says links are retired', async ({ page }) => {
    await page.goto('/ziti-network');
    await expect(page.getByRole('tab', { name: /remote access/i })).toBeVisible({ timeout: 10000 });
    await page.getByRole('tab', { name: /remote access/i }).click();
    await expect(page.locator('h3:has-text("BrowZer")')).toBeVisible({ timeout: 10000 });

    const section = page.locator('[data-testid="temp-access-section"]');
    await expect(section).toBeVisible({ timeout: 10000 });
    await expect(section.getByText('Support Access - Server 1')).toBeVisible();
    await expect(section.getByText('2 uses')).toBeVisible();
    await expect(section.getByText(/no longer open sessions/)).toBeVisible();
    await expect(section.getByRole('button', { name: /create/i })).toHaveCount(0);
    await expect(section.getByText(/temp-access\/abc/)).toHaveCount(0);
  });
});
