import { test, expect } from '@playwright/test';

test.describe('Users Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the users API
    await page.route('**/api/v1/identity/users*', async (route) => {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';

      const allUsers = [
        { id: '1', username: 'admin', email: 'admin@openidx.local', first_name: 'Admin', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
        { id: '2', username: 'john.doe', email: 'john@example.com', first_name: 'John', last_name: 'Doe', enabled: true, email_verified: false, created_at: '2024-01-15T00:00:00Z' },
        { id: '3', username: 'jane.smith', email: 'jane@example.com', first_name: 'Jane', last_name: 'Smith', enabled: false, email_verified: true, created_at: '2024-02-01T00:00:00Z' },
        { id: '4', username: 'bob.wilson', email: 'bob@example.com', first_name: 'Bob', last_name: 'Wilson', enabled: true, email_verified: true, created_at: '2024-02-15T00:00:00Z' },
      ];

      const filteredUsers = search
        ? allUsers.filter(u =>
            u.username.toLowerCase().includes(search.toLowerCase()) ||
            u.email.toLowerCase().includes(search.toLowerCase()) ||
            u.first_name.toLowerCase().includes(search.toLowerCase()) ||
            u.last_name.toLowerCase().includes(search.toLowerCase())
          )
        : allUsers;

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': String(filteredUsers.length) },
        body: JSON.stringify(filteredUsers),
      });
    });

    // Mock roles API
    await page.route('**/api/v1/identity/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'role-1', name: 'admin', description: 'Administrator role', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
          { id: 'role-2', name: 'user', description: 'Regular user role', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
          { id: 'role-3', name: 'viewer', description: 'Read-only access', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
        ]),
      });
    });
  });

  test('should display users list page', async ({ page }) => {
    await page.goto('/users');

    await expect(page.locator('h1:has-text("Users")')).toBeVisible();
    await expect(page.locator('text=Manage user accounts and access')).toBeVisible();
  });

  test('should display user data in table', async ({ page }) => {
    await page.goto('/users');

    // Wait for users to load
    await expect(page.locator('text=admin@openidx.local').first()).toBeVisible();
    await expect(page.locator('text=john@example.com').first()).toBeVisible();
    await expect(page.locator('text=jane@example.com').first()).toBeVisible();
    await expect(page.locator('text=bob@example.com').first()).toBeVisible();
  });

  test('should display user status badges', async ({ page }) => {
    await page.goto('/users');

    // Check for Active and Disabled badges
    await expect(page.locator('text=Active').first()).toBeVisible();
    await expect(page.locator('text=Disabled')).toBeVisible();
  });

  test('should display email verified badge', async ({ page }) => {
    await page.goto('/users');

    // Admin user should have verified badge
    await expect(page.locator('text=Verified').first()).toBeVisible();
  });

  test('should have Add User button', async ({ page }) => {
    await page.goto('/users');

    await expect(page.getByRole('button', { name: /add user/i })).toBeVisible();
  });

  test('should have Export CSV button', async ({ page }) => {
    await page.goto('/users');

    await expect(page.getByRole('button', { name: /export csv/i })).toBeVisible();
  });

  test('should have Import CSV button', async ({ page }) => {
    await page.goto('/users');

    await expect(page.getByRole('button', { name: /import csv/i })).toBeVisible();
  });

  test('should have search input', async ({ page }) => {
    await page.goto('/users');

    await expect(page.getByPlaceholder(/search users/i)).toBeVisible();
  });

  test('should filter users by search', async ({ page }) => {
    await page.goto('/users');

    // Wait for initial load
    await expect(page.locator('text=admin@openidx.local').first()).toBeVisible();

    // Search for john
    await page.getByPlaceholder(/search users/i).fill('john');

    // Wait for filter to apply
    await expect(page.locator('text=john@example.com')).toBeVisible();
    await expect(page.locator('text=jane@example.com')).not.toBeVisible();
  });

  test('should show no users message when search has no results', async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';

      if (search === 'nonexistent') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '0' },
          body: JSON.stringify([]),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '4' },
          body: JSON.stringify([
            { id: '1', username: 'admin', email: 'admin@openidx.local', first_name: 'Admin', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
          ]),
        });
      }
    });

    await page.goto('/users');
    await page.getByPlaceholder(/search users/i).fill('nonexistent');

    await expect(page.locator('text=No users found')).toBeVisible();
  });
});

test.describe('Add User Modal', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-user-id',
            ...body,
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '0' },
          body: JSON.stringify([]),
        });
      }
    });

    await page.route('**/api/v1/identity/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });
  });

  test('should open add user modal when clicking Add User button', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    await expect(page.locator('text=Add New User')).toBeVisible();
  });

  test('should display all form fields in add user modal', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    await expect(page.getByLabel(/username/i)).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/first name/i)).toBeVisible();
    await expect(page.getByLabel(/last name/i)).toBeVisible();
  });

  test('should close modal when clicking Cancel', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();
    await expect(page.locator('text=Add New User')).toBeVisible();

    await page.getByRole('button', { name: /cancel/i }).click();

    await expect(page.locator('text=Add New User')).not.toBeVisible();
  });

  test('should validate required username field', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    // Fill only email
    await page.getByLabel(/email/i).fill('test@example.com');

    // Try to submit
    await page.getByRole('button', { name: /create user/i }).click();

    // Modal should still be visible (form not submitted)
    await expect(page.locator('text=Add New User')).toBeVisible();
  });

  test('should validate required email field', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    // Fill only username
    await page.getByLabel(/username/i).fill('testuser');

    // Try to submit
    await page.getByRole('button', { name: /create user/i }).click();

    // Modal should still be visible (form not submitted)
    await expect(page.locator('text=Add New User')).toBeVisible();
  });

  test('should validate email format', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    await page.getByLabel(/username/i).fill('testuser');
    await page.getByLabel(/email/i).fill('invalid-email');

    await page.getByRole('button', { name: /create user/i }).click();

    // Modal should still be visible due to invalid email
    await expect(page.locator('text=Add New User')).toBeVisible();
  });

  test('should create user successfully', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    await page.getByLabel(/username/i).fill('newuser');
    await page.getByLabel(/email/i).fill('newuser@example.com');
    await page.getByLabel(/first name/i).fill('New');
    await page.getByLabel(/last name/i).fill('User');

    await page.getByRole('button', { name: /create user/i }).click();

    // Modal should close on success
    await expect(page.locator('text=Add New User')).not.toBeVisible({ timeout: 5000 });

    // Success toast should appear
    await expect(page.locator('text=created successfully').first()).toBeVisible();
  });

  test('should show error on create failure', async ({ page }) => {
    await page.route('**/api/v1/identity/users', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Username already exists' }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '0' },
          body: JSON.stringify([]),
        });
      }
    });

    await page.route('**/api/v1/identity/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });

    await page.goto('/users');

    await page.getByRole('button', { name: /add user/i }).click();

    await page.getByLabel(/username/i).fill('existinguser');
    await page.getByLabel(/email/i).fill('existing@example.com');

    await page.getByRole('button', { name: /create user/i }).click();

    // Error toast should appear
    await expect(page.locator('text=Failed to create user').first()).toBeVisible();
  });
});

test.describe('User Actions', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '2' },
          body: JSON.stringify([
            { id: '1', username: 'admin', email: 'admin@openidx.local', first_name: 'Admin', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
            { id: '2', username: 'testuser', email: 'test@example.com', first_name: 'Test', last_name: 'User', enabled: true, email_verified: false, created_at: '2024-01-15T00:00:00Z' },
          ]),
        });
      }
    });

    await page.route('**/api/v1/identity/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'role-1', name: 'admin', description: 'Administrator', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
          { id: 'role-2', name: 'user', description: 'Regular user', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
        ]),
      });
    });
  });

  test('should open action menu when clicking more button', async ({ page }) => {
    await page.goto('/users');

    // Wait for users to load
    await expect(page.locator('text=admin@openidx.local').first()).toBeVisible();

    // Click the more actions button for the first user
    const actionButton = page.locator('tr').filter({ hasText: 'admin@openidx.local' }).getByRole('button');
    await actionButton.click();

    // Check dropdown menu items
    await expect(page.locator('text=Edit User')).toBeVisible();
    await expect(page.locator('text=Reset Password')).toBeVisible();
    await expect(page.locator('text=Manage Roles')).toBeVisible();
    await expect(page.locator('text=Delete User')).toBeVisible();
  });

  test('should open edit user modal', async ({ page }) => {
    await page.goto('/users');

    await expect(page.locator('text=admin@openidx.local').first()).toBeVisible();

    const actionButton = page.locator('tr').filter({ hasText: 'admin@openidx.local' }).getByRole('button');
    await actionButton.click();

    await page.locator('text=Edit User').click();

    await expect(page.locator('text=Edit User').first()).toBeVisible();

    // Form should be pre-filled with user data
    await expect(page.getByLabel(/username/i)).toHaveValue('admin');
  });

  test('should show reset password confirmation', async ({ page }) => {
    await page.goto('/users');

    await expect(page.locator('text=admin@openidx.local').first()).toBeVisible();

    const actionButton = page.locator('tr').filter({ hasText: 'admin@openidx.local' }).getByRole('button');
    await actionButton.click();

    await page.locator('text=Reset Password').click();

    await expect(page.getByRole('heading', { name: 'Are you sure?' })).toBeVisible();
    await expect(page.locator('text=reset the password for "admin"')).toBeVisible();
  });

  test('should show delete user confirmation', async ({ page }) => {
    await page.goto('/users');

    await expect(page.locator('text=testuser').first()).toBeVisible();

    const actionButton = page.locator('tr').filter({ hasText: 'test@example.com' }).getByRole('button');
    await actionButton.click();

    await page.locator('text=Delete User').click();

    await expect(page.getByRole('heading', { name: 'Are you sure?' })).toBeVisible();
    await expect(page.locator('text=delete user "testuser"')).toBeVisible();
  });

  test('should cancel delete user confirmation', async ({ page }) => {
    await page.goto('/users');

    await expect(page.locator('text=testuser').first()).toBeVisible();

    const actionButton = page.locator('tr').filter({ hasText: 'test@example.com' }).getByRole('button');
    await actionButton.click();

    await page.locator('text=Delete User').click();

    await expect(page.getByRole('heading', { name: 'Are you sure?' })).toBeVisible();

    await page.getByRole('button', { name: /cancel/i }).click();

    await expect(page.getByRole('heading', { name: 'Are you sure?' })).not.toBeVisible();
  });

  test('should open manage roles modal', async ({ page }) => {
    await page.route('**/api/v1/identity/users/1/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'role-1', name: 'admin', description: 'Administrator', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
        ]),
      });
    });

    await page.goto('/users');

    await expect(page.locator('text=admin@openidx.local').first()).toBeVisible();

    const actionButton = page.locator('tr').filter({ hasText: 'admin@openidx.local' }).getByRole('button');
    await actionButton.click();

    await page.locator('text=Manage Roles').click();

    await expect(page.locator('text=Manage Roles - admin')).toBeVisible();
    await expect(page.locator('text=Available Roles')).toBeVisible();
  });
});

test.describe('Import/Export Users', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '0' },
        body: JSON.stringify([]),
      });
    });

    await page.route('**/api/v1/identity/roles', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });
  });

  test('should open import modal', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /import csv/i }).click();

    await expect(page.locator('text=Import Users from CSV')).toBeVisible();
    await expect(page.getByLabel('CSV File')).toBeVisible();
  });

  test('should show CSV format hint', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /import csv/i }).click();

    await expect(page.locator('text=username, email, first_name, last_name')).toBeVisible();
  });

  test('should disable import button when no file selected', async ({ page }) => {
    await page.goto('/users');

    await page.getByRole('button', { name: /import csv/i }).click();

    const importButton = page.getByRole('button', { name: /^import$/i });
    await expect(importButton).toBeDisabled();
  });
});
