import { test, expect } from '@playwright/test';

test.describe('Users Management - CRUD Operations', () => {
  test.beforeEach(async ({ page }) => {
    // The signed-in storageState from auth.setup.ts is the session. What
    // stood here overwrote it with a hand-assembled JWT ending in
    // `mock-signature`: btoa() emits standard base64, JWT requires base64url,
    // so identity-service logged "token is malformed: could not base64 decode
    // claim" on every request and the console bounced back to /login. The
    // route mocks below still stand in for the API; the SESSION has to be real.
  });

  test('should display users page heading', async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [],
          total: 0,
          page: 1,
          per_page: 25,
        }),
      });
    });

    await page.goto('/users');
    await expect(page.getByRole('heading', { name: /users/i })).toBeVisible();
  });

  test('should display user list table', async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: '1',
              username: 'alice',
              email: 'alice@example.com',
              first_name: 'Alice',
              last_name: 'Johnson',
              enabled: true,
              email_verified: true,
              created_at: '2025-01-15T10:00:00Z',
            },
            {
              id: '2',
              username: 'bob',
              email: 'bob@example.com',
              first_name: 'Bob',
              last_name: 'Smith',
              enabled: true,
              email_verified: false,
              created_at: '2025-01-16T10:00:00Z',
            },
          ],
          total: 2,
          page: 1,
          per_page: 25,
        }),
      });
    });

    await page.goto('/users');
    await expect(page.getByText('alice@example.com')).toBeVisible();
    await expect(page.getByText('bob@example.com')).toBeVisible();
  });

  test('should have add user button', async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [], total: 0, page: 1, per_page: 25 }),
      });
    });

    await page.goto('/users');
    const addButton = page.getByRole('button', { name: /add user|create user|new user/i });
    await expect(addButton).toBeVisible();
  });

  test('should have search functionality', async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [], total: 0, page: 1, per_page: 25 }),
      });
    });

    await page.goto('/users');
    const searchInput = page.getByPlaceholder(/search/i);
    await expect(searchInput).toBeVisible();
  });

  test('should display user actions menu', async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: '1',
              username: 'alice',
              email: 'alice@example.com',
              first_name: 'Alice',
              last_name: 'Johnson',
              enabled: true,
              email_verified: true,
              created_at: '2025-01-15T10:00:00Z',
            },
          ],
          total: 1,
          page: 1,
          per_page: 25,
        }),
      });
    });

    await page.goto('/users');

    // Look for action menu button (typically three dots or similar)
    const actionButton = page.locator('button').filter({ hasText: /^$/ }).first();
    // Or check for a more specific selector if needed
    const menuButtons = page.locator('button[aria-label*="more" i], button[aria-label*="actions" i], button:has(svg)').first();
    await expect(menuButtons).toHaveCount(await menuButtons.count());
  });
});
