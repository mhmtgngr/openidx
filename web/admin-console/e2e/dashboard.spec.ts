import { test, expect } from '@playwright/test';

test.describe('Dashboard Page', () => {
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

    // Mock API responses
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 1250,
          active_users: 843,
          total_groups: 45,
          total_applications: 23,
          active_sessions: 312,
          pending_reviews: 7,
          security_alerts: 2,
          recent_activity: [
            {
              id: '1',
              type: 'authentication',
              message: 'User alice@example.com logged in',
              timestamp: new Date(Date.now() - 300000).toISOString(),
            },
            {
              id: '2',
              type: 'user_management',
              message: 'New user bob@example.com created',
              timestamp: new Date(Date.now() - 900000).toISOString(),
            },
          ],
          auth_stats: {
            total_logins: 5432,
            successful_logins: 5102,
            failed_logins: 330,
            mfa_usage: 0.85,
            logins_by_method: { password: 3200, sso: 1902, webauthn: 330 },
          },
          security_alert_details: [
            { message: 'Multiple failed login attempts', count: 5, timestamp: new Date(Date.now() - 3600000).toISOString() },
          ],
        }),
      });
    });

    await page.route('**/api/v1/analytics/logins*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            { date: '2025-02-20', successful: 450, failed: 12 },
            { date: '2025-02-21', successful: 520, failed: 8 },
            { date: '2025-02-22', successful: 480, failed: 15 },
            { date: '2025-02-23', successful: 510, failed: 10 },
          ],
        }),
      });
    });

    await page.route('**/api/v1/analytics/risk*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            { level: 'Low', count: 850 },
            { level: 'Medium', count: 120 },
            { level: 'High', count: 25 },
            { level: 'Critical', count: 5 },
          ],
        }),
      });
    });

    await page.route('**/api/v1/analytics/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            { event_type: 'login.success', count: 3200 },
            { event_type: 'user.created', count: 45 },
            { event_type: 'mfa.enabled', count: 120 },
            { event_type: 'password.changed', count: 85 },
          ],
        }),
      });
    });

    await page.goto('/dashboard');
  });

  test('should display dashboard heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  });

  test('should display stat cards', async ({ page }) => {
    await expect(page.getByText('Total Users')).toBeVisible();
    await expect(page.getByText('1,250')).toBeVisible();
    await expect(page.getByText('Applications')).toBeVisible();
    await expect(page.getByText('Active Sessions')).toBeVisible();
    await expect(page.getByText('Pending Reviews')).toBeVisible();
  });

  test('should display security alerts section', async ({ page }) => {
    await expect(page.getByText('Security Alerts')).toBeVisible();
  });

  test('should display recent activity section', async ({ page }) => {
    await expect(page.getByText('Recent Activity')).toBeVisible();
    await expect(page.getByText('User alice@example.com logged in')).toBeVisible();
  });

  test('should display analytics section', async ({ page }) => {
    await expect(page.getByText('Analytics')).toBeVisible();
    await expect(page.getByText('Login Activity')).toBeVisible();
  });

  test('should have period selector buttons', async ({ page }) => {
    await expect(page.getByRole('button', { name: '7d' })).toBeVisible();
    await expect(page.getByRole('button', { name: '30d' })).toBeVisible();
    await expect(page.getByRole('button', { name: '90d' })).toBeVisible();
  });

  test('should navigate to users page when clicking Total Users card', async ({ page }) => {
    await page.getByText('Total Users').first().click();
    await expect(page).toHaveURL(/\/users/);
  });

  test('should navigate to applications page when clicking Applications card', async ({ page }) => {
    await page.getByText('Applications').first().click();
    await expect(page).toHaveURL(/\/applications/);
  });
});
