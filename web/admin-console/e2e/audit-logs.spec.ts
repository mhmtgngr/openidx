import { test, expect } from '@playwright/test';

test.describe('Audit Logs', () => {
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

    // Mock audit logs API
    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'evt-1',
              event_type: 'user.login.success',
              actor_id: 'user-1',
              actor_name: 'alice@example.com',
              resource_type: 'user',
              resource_id: 'user-1',
              action: 'login',
              outcome: 'success',
              timestamp: '2025-02-23T10:30:00Z',
              ip_address: '192.168.1.100',
              user_agent: 'Mozilla/5.0...',
            },
            {
              id: 'evt-2',
              event_type: 'user.created',
              actor_id: 'admin-1',
              actor_name: 'admin@example.com',
              resource_type: 'user',
              resource_id: 'user-2',
              action: 'create',
              outcome: 'success',
              timestamp: '2025-02-23T09:15:00Z',
              ip_address: '192.168.1.10',
              user_agent: 'Mozilla/5.0...',
            },
            {
              id: 'evt-3',
              event_type: 'user.login.failed',
              actor_id: 'user-3',
              actor_name: 'bob@example.com',
              resource_type: 'user',
              resource_id: 'user-3',
              action: 'login',
              outcome: 'failure',
              timestamp: '2025-02-23T08:45:00Z',
              ip_address: '192.168.1.200',
              user_agent: 'Mozilla/5.0...',
              reason: 'Invalid password',
            },
          ],
          total: 3,
          page: 1,
          per_page: 50,
        }),
      });
    });
  });

  test('should display audit logs page heading', async ({ page }) => {
    await page.goto('/audit-logs');
    await expect(page.getByRole('heading', { name: /audit logs/i })).toBeVisible();
  });

  test('should display list of audit events', async ({ page }) => {
    await page.goto('/audit-logs');
    await expect(page.getByText('user.login.success')).toBeVisible();
    await expect(page.getByText('user.created')).toBeVisible();
    await expect(page.getByText('user.login.failed')).toBeVisible();
  });

  test('should have filter controls', async ({ page }) => {
    await page.goto('/audit-logs');

    // Check for common filter elements
    const dateFilter = page.getByPlaceholder(/date|from|to/i);
    const eventFilter = page.getByPlaceholder(/event|type/i);

    // At least some filter controls should be present
    const filterVisible = await dateFilter.count() > 0 || await eventFilter.count() > 0;
    expect(filterVisible).toBe(true);
  });

  test('should display event details', async ({ page }) => {
    await page.goto('/audit-logs');
    await expect(page.getByText('alice@example.com')).toBeVisible();
    await expect(page.getByText('admin@example.com')).toBeVisible();
  });

  test('should have export functionality', async ({ page }) => {
    await page.goto('/audit-logs');
    const exportButton = page.getByRole('button', { name: /export|download|csv/i });
    await expect(exportButton).toBeVisible();
  });
});
