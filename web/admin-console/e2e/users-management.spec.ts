import { test, expect } from '@playwright/test';
import { LoginPage } from './pages/login.page';
import { UsersPage } from './pages/users.page';

/**
 * User Management E2E Tests
 * Tests for listing, creating, editing, and deleting users
 */

const mockUsers = [
  { id: '1', username: 'admin', email: 'admin@openidx.local', first_name: 'Admin', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
  { id: '2', username: 'john.doe', email: 'john@example.com', first_name: 'John', last_name: 'Doe', enabled: true, email_verified: false, created_at: '2024-01-15T00:00:00Z' },
  { id: '3', username: 'jane.smith', email: 'jane@example.com', first_name: 'Jane', last_name: 'Smith', enabled: false, email_verified: true, created_at: '2024-02-01T00:00:00Z' },
  { id: '4', username: 'bob.wilson', email: 'bob@example.com', first_name: 'Bob', last_name: 'Wilson', enabled: true, email_verified: true, created_at: '2024-02-15T00:00:00Z' },
];

test.describe('Users Page - List and Search', () => {
  let usersPage: UsersPage;

  test.beforeEach(async ({ page }) => {
    usersPage = new UsersPage(page);

    // Mock authentication
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock users API
    await page.route('**/api/v1/identity/users*', async (route) => {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);
      const limit = parseInt(url.searchParams.get('limit') || '20', 10);

      let filteredUsers = mockUsers;

      // Apply search filter
      if (search) {
        filteredUsers = mockUsers.filter(u =>
          u.username.toLowerCase().includes(search.toLowerCase()) ||
          u.email.toLowerCase().includes(search.toLowerCase()) ||
          u.first_name.toLowerCase().includes(search.toLowerCase()) ||
          u.last_name.toLowerCase().includes(search.toLowerCase())
        );
      }

      // Apply pagination
      const paginatedUsers = filteredUsers.slice(offset, offset + limit);

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': String(filteredUsers.length) },
        body: JSON.stringify(paginatedUsers),
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
        ]),
      });
    });
  });

  test('should display users list page', async ({ page }) => {
    await usersPage.goto();

    await expect(usersPage.pageTitle).toBeVisible();
    await expect(usersPage.pageDescription).toBeVisible();
    await expect(usersPage.addUserButton).toBeVisible();
    await expect(usersPage.searchInput).toBeVisible();
  });

  test('should display all users in table', async ({ page }) => {
    await usersPage.goto();

    const userCount = await usersPage.getUserCount();
    expect(userCount).toBeGreaterThan(0);

    // Check for known users
    await expect(page.locator('text=admin@openidx.local')).toBeVisible();
    await expect(page.locator('text=john@example.com')).toBeVisible();
  });

  test('should display user status badges', async ({ page }) => {
    await usersPage.goto();

    // Check for Active badge
    const adminStatus = await usersPage.getUserStatus('admin');
    expect(adminStatus).toContain('Active');

    // Check for Disabled badge
    const janeStatus = await usersPage.getUserStatus('jane.smith');
    expect(janeStatus).toContain('Disabled');
  });

  test('should display email verified badge', async ({ page }) => {
    await usersPage.goto();

    const adminRow = await usersPage.getUserRow('admin');
    await expect(adminRow.locator('text=Verified')).toBeVisible();
  });

  test('should filter users by search', async ({ page }) => {
    await usersPage.goto();

    // Initial count
    const initialCount = await usersPage.getUserCount();

    // Search for specific user
    await usersPage.search('john');

    const filteredCount = await usersPage.getUserCount();
    expect(filteredCount).toBeLessThan(initialCount);
    await expect(page.locator('text=john@example.com')).toBeVisible();
  });

  test('should show no users message when search has no results', async ({ page }) => {
    // Override mock to return empty results for specific search
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
          body: JSON.stringify(mockUsers),
        });
      }
    });

    await usersPage.goto();
    await usersPage.search('nonexistent');

    await expect(usersPage.noUsersMessage).toBeVisible();
  });

  test('should have action buttons in header', async ({ page }) => {
    await usersPage.goto();

    await expect(usersPage.addUserButton).toBeVisible();
    await expect(usersPage.exportCSVButton).toBeVisible();
    await expect(usersPage.importCSVButton).toBeVisible();
  });
});

test.describe('Create User', () => {
  let usersPage: UsersPage;

  test.beforeEach(async ({ page }) => {
    usersPage = new UsersPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    await page.route('**/api/v1/identity/users*', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-user-id',
            ...body,
            enabled: true,
            email_verified: false,
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

  test('should open add user modal', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openAddUserModal();

    await expect(usersPage.addUserDialogTitle).toBeVisible();
  });

  test('should display all form fields in add user modal', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openAddUserModal();

    await expect(usersPage.usernameInput).toBeVisible();
    await expect(usersPage.emailInput).toBeVisible();
    await expect(usersPage.firstNameInput).toBeVisible();
    await expect(usersPage.lastNameInput).toBeVisible();
  });

  test('should create user with valid data', async ({ page }) => {
    await usersPage.goto();

    await usersPage.createUser({
      username: 'newuser',
      email: 'newuser@example.com',
      firstName: 'New',
      lastName: 'User',
    });

    // Verify success toast
    await expect(page.locator('text=/created successfully/i')).toBeVisible();
  });

  test('should show validation errors for missing required fields', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openAddUserModal();

    // Try to submit without filling form
    await usersPage.submitCreateUser();

    // Modal should still be visible (HTML5 validation or form prevented submission)
    await expect(usersPage.addUserDialogTitle).toBeVisible();
  });

  test('should validate email format', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openAddUserModal();

    await usersPage.fillUserForm({
      username: 'testuser',
      email: 'invalid-email',
    });

    await usersPage.submitCreateUser();

    // Browser's HTML5 validation should prevent submission
    await expect(usersPage.addUserDialogTitle).toBeVisible();
  });

  test('should close modal on cancel', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openAddUserModal();

    await usersPage.cancelButton.click();

    await expect(usersPage.addUserDialogTitle).not.toBeVisible();
  });

  test('should show error on create failure', async ({ page }) => {
    await page.route('**/api/v1/identity/users', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Username already exists' }),
        });
      }
    });

    await usersPage.goto();

    await usersPage.createUser({
      username: 'existinguser',
      email: 'existing@example.com',
    });

    // Verify error toast
    await expect(page.locator('text=/failed to create user/i')).toBeVisible();
  });
});

test.describe('Edit User', () => {
  let usersPage: UsersPage;

  test.beforeEach(async ({ page }) => {
    usersPage = new UsersPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

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
      } else if (route.request().method() === 'PUT') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: '2',
            username: 'testuser-updated',
            email: 'test-updated@example.com',
            first_name: 'Test',
            last_name: 'User Updated',
            enabled: true,
            email_verified: false,
            created_at: '2024-01-15T00:00:00Z',
          }),
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

  test('should open edit user modal', async ({ page }) => {
    await usersPage.goto();

    await usersPage.editUser('testuser');

    await expect(usersPage.editUserDialogTitle).toBeVisible();
  });

  test('should pre-fill form with existing user data', async ({ page }) => {
    await usersPage.goto();

    await usersPage.editUser('testuser');

    await expect(usersPage.usernameInput).toHaveValue('testuser');
    await expect(usersPage.emailInput).toHaveValue('test@example.com');
  });

  test('should update user information', async ({ page }) => {
    await usersPage.goto();

    await usersPage.editUser('testuser');

    await usersPage.updateUser({
      username: 'testuser-updated',
      email: 'test-updated@example.com',
      lastName: 'User Updated',
    });

    // Verify success toast
    await expect(page.locator('text=/updated successfully/i')).toBeVisible();
  });
});

test.describe('Delete User', () => {
  let usersPage: UsersPage;

  test.beforeEach(async ({ page }) => {
    usersPage = new UsersPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    await page.route('**/api/v1/identity/users*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '2' },
          body: JSON.stringify([
            { id: '1', username: 'admin', email: 'admin@openidx.local', first_name: 'Admin', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
            { id: '2', username: 'todelete', email: 'delete@example.com', first_name: 'To', last_name: 'Delete', enabled: true, email_verified: false, created_at: '2024-01-15T00:00:00Z' },
          ]),
        });
      } else if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'User deleted' }),
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

  test('should show delete confirmation dialog', async ({ page }) => {
    await usersPage.goto();

    await usersPage.openUserActions('todelete');
    await page.getByRole('menuitem', { name: /delete user/i }).click();

    await expect(usersPage.deleteConfirmationTitle).toBeVisible();
    await expect(page.locator('text=/delete user "todelete"/i')).toBeVisible();
  });

  test('should delete user after confirmation', async ({ page }) => {
    await usersPage.goto();

    await usersPage.deleteUser('todelete');

    // Verify success toast
    await expect(page.locator('text=/deleted successfully/i')).toBeVisible();
  });

  test('should cancel delete operation', async ({ page }) => {
    await usersPage.goto();

    await usersPage.openUserActions('todelete');
    await page.getByRole('menuitem', { name: /delete user/i }).click();

    await usersPage.cancelButton.click();

    // Confirmation dialog should close
    await expect(usersPage.deleteConfirmationTitle).not.toBeVisible();
  });
});

test.describe('Password Reset', () => {
  let usersPage: UsersPage;

  test.beforeEach(async ({ page }) => {
    usersPage = new UsersPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    await page.route('**/api/v1/identity/users*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '1' },
          body: JSON.stringify([
            { id: '1', username: 'testuser', email: 'test@example.com', first_name: 'Test', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
          ]),
        });
      } else if (route.request().method() === 'POST' && route.request().url().includes('reset-password')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Password reset email sent' }),
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

  test('should show password reset confirmation', async ({ page }) => {
    await usersPage.goto();

    await usersPage.initiatePasswordReset('testuser');

    await expect(usersPage.resetPasswordConfirmationTitle).toBeVisible();
    await expect(page.locator('text=/reset the password for "testuser"/i')).toBeVisible();
  });

  test('should confirm password reset', async ({ page }) => {
    await usersPage.goto();

    await usersPage.initiatePasswordReset('testuser');
    await usersPage.confirmPasswordReset();

    // Verify success toast
    await expect(page.locator('text=/password reset email sent/i')).toBeVisible();
  });
});

test.describe('Import/Export Users', () => {
  let usersPage: UsersPage;

  test.beforeEach(async ({ page }) => {
    usersPage = new UsersPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    await page.route('**/api/v1/identity/users*', async (route) => {
      if (route.request().method() === 'GET') {
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

  test('should open import modal', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openImportModal();

    await expect(usersPage.importDialogTitle).toBeVisible();
    await expect(usersPage.csvFileInput).toBeVisible();
  });

  test('should disable import button when no file selected', async ({ page }) => {
    await usersPage.goto();
    await usersPage.openImportModal();

    await expect(usersPage.importModalButton).toBeDisabled();
  });

  test('should complete CSV import', async ({ page }) => {
    await page.route('**/api/v1/identity/users/import', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total: 10,
          created: 8,
          errors: 2,
          details: ['Line 5: Invalid email format', 'Line 8: Duplicate username'],
        }),
      });
    });

    await usersPage.goto();
    await usersPage.openImportModal();

    // Create a temporary CSV file using Playwright's tmp file handling
    const csvPath = '/tmp/test-users.csv';
    await page.evaluate(() => {
      // Write file in browser context (for testing purposes, we'll mock this)
      // In real tests, you'd use page.setInputFiles() with a file from the fixtures
    });

    // Instead of creating a real file, we'll set input directly with a buffer
    await page.evaluate(() => {
      const dt = new DataTransfer();
      const file = new File(['username,email,first_name,last_name\nuser1,user1@test.com,Test,User1'], 'test-users.csv', { type: 'text/csv' });
      dt.items.add(file);
      const input = document.querySelector('input[type="file"]') as HTMLInputElement;
      if (input) {
        input.files = dt.files;
      }
    });

    await usersPage.submitImport();

    // Should show import summary
    await expect(page.locator('text=/8 of 10 users imported/i')).toBeVisible();
  });

  test('should export users to CSV', async ({ page }) => {
    await page.route('**/api/v1/identity/users/export', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/csv',
        body: 'username,email,first_name,last_name\nadmin,admin@test.com,Admin,User',
      });
    });

    await usersPage.goto();

    const download = await usersPage.exportCSV();

    expect(download.suggestedFilename()).toContain('.csv');
  });
});
