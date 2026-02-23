import { test, expect } from '@playwright/test';

test.describe('Policies Management', () => {
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

    // Mock policies API
    await page.route('**/api/v1/governance/policies*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'policy-1',
              name: 'MFA Required for Admin Access',
              description: 'All admin users must have MFA enabled',
              type: 'authentication',
              status: 'active',
              priority: 1,
              created_at: '2025-01-15T10:00:00Z',
            },
            {
              id: 'policy-2',
              name: 'Password Expiration Policy',
              description: 'Passwords must be changed every 90 days',
              type: 'password',
              status: 'active',
              priority: 2,
              created_at: '2025-01-16T10:00:00Z',
            },
            {
              id: 'policy-3',
              name: 'Session Timeout Policy',
              description: 'Sessions timeout after 60 minutes of inactivity',
              type: 'session',
              status: 'active',
              priority: 3,
              created_at: '2025-01-17T10:00:00Z',
            },
          ],
          total: 3,
          page: 1,
          per_page: 25,
        }),
      });
    });
  });

  test('should display policies page heading', async ({ page }) => {
    await page.goto('/policies');
    await expect(page.getByRole('heading', { name: /policies/i })).toBeVisible();
  });

  test('should display list of policies', async ({ page }) => {
    await page.goto('/policies');
    await expect(page.getByText('MFA Required for Admin Access')).toBeVisible();
    await expect(page.getByText('Password Expiration Policy')).toBeVisible();
    await expect(page.getByText('Session Timeout Policy')).toBeVisible();
  });

  test('should show policy types', async ({ page }) => {
    await page.goto('/policies');
    await expect(page.getByText(/authentication/i)).toBeVisible();
    await expect(page.getByText(/password/i)).toBeVisible();
  });

  test('should have create policy button', async ({ page }) => {
    await page.goto('/policies');
    const createButton = page.getByRole('button', { name: /create|add|new policy/i });
    await expect(createButton).toBeVisible();
  });

  test('should display policy status badges', async ({ page }) => {
    await page.goto('/policies');
    await expect(page.getByText(/active/i)).toBeVisible();
  });
});
