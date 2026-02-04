import { test, expect } from '@playwright/test';

test.describe('User Profile Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the correct API endpoint
    await page.route('**/api/v1/identity/users/me', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'test-user-id',
            username: 'testuser',
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            phone: '+1234567890',
            emailVerified: true,
            mfaEnabled: false,
            enabled: true,
            created_at: '2024-01-01T00:00:00Z',
          }),
        });
      }
    });
  });

  test('should display user profile page', async ({ page }) => {
    await page.goto('/profile');

    // Page title is "My Profile"
    await expect(page.locator('h1:has-text("My Profile")')).toBeVisible();
  });

  test('should display user information', async ({ page }) => {
    await page.goto('/profile');

    // Profile shows email in the email field
    await expect(page.getByLabel(/email/i)).toBeVisible();
  });

  test('should have update profile button', async ({ page }) => {
    await page.goto('/profile');

    // The button is "Update Profile"
    await expect(page.getByRole('button', { name: /update profile/i })).toBeVisible();
  });

  test('should display MFA section in Security tab', async ({ page }) => {
    await page.goto('/profile');

    // MFA section is under the Security tab
    const securityTab = page.getByRole('tab', { name: /security/i });
    await expect(securityTab).toBeVisible();
    await securityTab.click();

    // Look for "Multi-Factor Authentication" heading
    await expect(page.getByText('Multi-Factor Authentication')).toBeVisible();
  });
});

test.describe('My Access Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the access overview API
    await page.route('**/api/v1/identity/portal/access-overview*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          roles_count: 2,
          groups_count: 1,
          apps_count: 2,
          pending_requests: 0,
          roles: [
            { id: 'role-1', name: 'user' },
            { id: 'role-2', name: 'developer' },
          ],
          groups: [
            { id: 'group-1', name: 'Engineering' },
          ],
        }),
      });
    });

    // Mock available groups
    await page.route('**/api/v1/identity/portal/groups/available*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ groups: [] }),
      });
    });

    // Mock group requests
    await page.route('**/api/v1/identity/portal/groups/requests*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ requests: [] }),
      });
    });
  });

  test('should display my access page', async ({ page }) => {
    await page.goto('/my-access');

    await expect(page.locator('h1:has-text("My Access")')).toBeVisible();
  });

  test('should display assigned roles section', async ({ page }) => {
    await page.goto('/my-access');

    // Look for "My Roles" heading
    await expect(page.getByRole('heading', { name: 'My Roles' })).toBeVisible();
  });
});

test.describe('My Devices Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the devices API - returns data in { data: { devices: [...] } } format
    await page.route('**/api/v1/identity/portal/devices*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              devices: [
                { id: '1', name: 'MacBook Pro', device_type: 'laptop', ip_address: '192.168.1.100', trusted: true, last_seen_at: '2024-01-20T12:00:00Z', created_at: '2024-01-01T00:00:00Z' },
                { id: '2', name: 'iPhone 15', device_type: 'mobile', ip_address: '192.168.1.101', trusted: true, last_seen_at: '2024-01-19T15:00:00Z', created_at: '2024-01-02T00:00:00Z' },
                { id: '3', name: 'Windows PC', device_type: 'desktop', ip_address: '192.168.1.102', trusted: false, last_seen_at: '2024-01-18T10:00:00Z', created_at: '2024-01-03T00:00:00Z' },
              ],
            },
          }),
        });
      }
    });
  });

  test('should display my devices page', async ({ page }) => {
    await page.goto('/my-devices');

    await expect(page.locator('h1:has-text("My Devices")')).toBeVisible();
  });

  test('should display list of devices', async ({ page }) => {
    await page.goto('/my-devices');

    // Look for device name
    await expect(page.getByText('MacBook Pro')).toBeVisible();
  });

  test('should show trust status indicator', async ({ page }) => {
    await page.goto('/my-devices');

    // Page shows "Trusted" or "Untrusted" badges
    await expect(page.getByText('Trusted').first()).toBeVisible();
  });

  test('should have remove device option in menu', async ({ page }) => {
    await page.goto('/my-devices');

    // Wait for devices to load
    await expect(page.getByText('MacBook Pro')).toBeVisible();

    // Look for the more menu button (MoreHorizontal icon button)
    const moreButton = page.locator('button').filter({ has: page.locator('svg.lucide-more-horizontal') }).first();

    // If the more button exists, we have the remove option
    const hasMoreButton = await moreButton.count() > 0;
    expect(hasMoreButton).toBeTruthy();
  });
});

test.describe('Trusted Browsers Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the trusted browsers API
    await page.route('**/api/v1/identity/trusted-browsers', async (route) => {
      if (route.request().method() === 'GET' && !route.request().url().includes('/check')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: [
              { id: '1', name: 'Chrome on macOS', ip_address: '192.168.1.100', active: true, revoked: false, trusted_at: '2024-01-15T10:00:00Z', expires_at: '2024-02-14T10:00:00Z' },
              { id: '2', name: 'Firefox on Windows', ip_address: '192.168.1.101', active: false, revoked: true, trusted_at: '2024-01-10T10:00:00Z', expires_at: '2024-02-09T10:00:00Z' },
            ],
          }),
        });
      }
    });

    // Mock the check endpoint
    await page.route('**/api/v1/identity/trusted-browsers/check*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: { trusted: false },
        }),
      });
    });
  });

  test('should display trusted browsers page', async ({ page }) => {
    await page.goto('/trusted-browsers');

    await expect(page.locator('h1:has-text("Trusted Browsers")')).toBeVisible();
  });

  test('should display list of trusted browsers', async ({ page }) => {
    await page.goto('/trusted-browsers');

    // Look for browser name
    await expect(page.getByText('Chrome on macOS')).toBeVisible();
  });

  test('should show expiration info', async ({ page }) => {
    await page.goto('/trusted-browsers');

    // Page shows "Expires in X days"
    await expect(page.getByText(/expires in/i).first()).toBeVisible();
  });

  test('should have revoke all button', async ({ page }) => {
    await page.goto('/trusted-browsers');

    // "Revoke All" button in header
    await expect(page.getByRole('button', { name: /revoke all/i })).toBeVisible();
  });
});

test.describe('Notification Preferences Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the notification preferences API
    await page.route('**/api/v1/identity/notifications/preferences*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            preferences: [
              { channel: 'in_app', event_type: 'security_alert', enabled: true },
              { channel: 'email', event_type: 'security_alert', enabled: true },
              { channel: 'in_app', event_type: 'access_request', enabled: true },
              { channel: 'email', event_type: 'access_request', enabled: false },
            ],
          }),
        });
      }
    });
  });

  test('should display notification preferences page', async ({ page }) => {
    await page.goto('/notification-preferences');

    await expect(page.locator('h1:has-text("Notification Preferences")')).toBeVisible();
  });

  test('should display notification toggles', async ({ page }) => {
    await page.goto('/notification-preferences');

    // Check for toggle buttons (custom styled buttons with rounded-full class)
    const toggles = page.locator('button.rounded-full');
    await expect(toggles.first()).toBeVisible();
  });

  test('should have security alerts option', async ({ page }) => {
    await page.goto('/notification-preferences');

    // Look for Security Alerts in the table (not the sidebar link)
    await expect(page.getByRole('table').getByText('Security Alerts')).toBeVisible();
  });

  test('should have email channel option', async ({ page }) => {
    await page.goto('/notification-preferences');

    // Email channel header
    await expect(page.getByText('Email', { exact: true })).toBeVisible();
  });
});

test.describe('Access Requests Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock my requests
    await page.route('**/api/v1/governance/requests*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          requests: [
            { id: '1', resource_type: 'role', resource_name: 'admin', status: 'pending', justification: 'Need admin access', created_at: '2024-01-20T10:00:00Z', requester_name: 'Test User' },
            { id: '2', resource_type: 'application', resource_name: 'Finance Portal', status: 'approved', justification: 'Quarterly reporting', created_at: '2024-01-15T10:00:00Z', requester_name: 'Test User' },
          ],
        }),
      });
    });

    // Mock my approvals
    await page.route('**/api/v1/governance/my-approvals*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ pending_approvals: [] }),
      });
    });
  });

  test('should display access requests page', async ({ page }) => {
    await page.goto('/access-requests');

    await expect(page.locator('h1:has-text("Access Requests")')).toBeVisible();
  });

  test('should display request list', async ({ page }) => {
    await page.goto('/access-requests');

    // Look for resource name in the table
    await expect(page.getByText('admin').first()).toBeVisible();
  });

  test('should show request status', async ({ page }) => {
    await page.goto('/access-requests');

    // Status badge shows pending or approved
    await expect(page.getByText('pending').first()).toBeVisible();
  });

  test('should have request access button', async ({ page }) => {
    await page.goto('/access-requests');

    // Button is "Request Access"
    await expect(page.getByRole('button', { name: /request access/i })).toBeVisible();
  });
});

test.describe('App Launcher Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock the applications API
    await page.route('**/api/v1/identity/portal/applications*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          applications: [
            { id: '1', name: 'Admin Console', description: 'OpenIDX Admin Dashboard', base_url: 'https://admin.example.com', protocol: 'oidc', logo_url: '', sso_enabled: true },
            { id: '2', name: 'Developer Portal', description: 'API Documentation', base_url: 'https://dev.example.com', protocol: 'saml', logo_url: '', sso_enabled: true },
          ],
        }),
      });
    });
  });

  test('should display app launcher page', async ({ page }) => {
    await page.goto('/app-launcher');

    // h1 is "My Applications"
    await expect(page.locator('h1:has-text("My Applications")')).toBeVisible();
  });

  test('should display available applications', async ({ page }) => {
    await page.goto('/app-launcher');

    // Application names appear as card titles
    await expect(page.getByText('Admin Console')).toBeVisible();
    await expect(page.getByText('Developer Portal')).toBeVisible();
  });

  test('should have clickable app cards with launch button', async ({ page }) => {
    await page.goto('/app-launcher');

    // Each card has a "Launch" button
    await expect(page.getByRole('button', { name: /launch/i }).first()).toBeVisible();
  });

  test('should have search functionality', async ({ page }) => {
    await page.goto('/app-launcher');

    // Search input with placeholder
    const searchInput = page.getByPlaceholder(/search applications/i);
    await expect(searchInput).toBeVisible();
  });
});

test.describe('Password Change Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/users/me', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'test-user-id',
            username: 'testuser',
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            mfaEnabled: false,
            enabled: true,
          }),
        });
      }
    });
  });

  test('should have change password section on profile security tab', async ({ page }) => {
    await page.goto('/profile');

    // Go to security tab
    const securityTab = page.getByRole('tab', { name: /security/i });
    await securityTab.click();

    // Look for Change Password heading
    await expect(page.getByRole('heading', { name: 'Change Password' })).toBeVisible();
  });
});

test.describe('MFA Setup Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/users/me', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'test-user-id',
            username: 'testuser',
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            mfaEnabled: false,
            enabled: true,
          }),
        });
      }
    });

    await page.route('**/api/v1/identity/mfa/methods*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });

    await page.route('**/api/v1/identity/trusted-browsers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });
  });

  test('should show MFA setup option when MFA is not enabled', async ({ page }) => {
    await page.goto('/profile');

    // Go to security tab
    const securityTab = page.getByRole('tab', { name: /security/i });
    await securityTab.click();

    // Look for Setup MFA button
    await expect(page.getByRole('button', { name: /setup mfa/i })).toBeVisible();
  });
});

test.describe('Session Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/users/me', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'test-user-id',
            username: 'testuser',
            email: 'test@example.com',
            firstName: 'Test',
            lastName: 'User',
            mfaEnabled: false,
            enabled: true,
          }),
        });
      }
    });

    // Mock sessions API
    await page.route('**/api/v1/identity/users/*/sessions*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', ip_address: '192.168.1.100', user_agent: 'Chrome/120 on macOS', started_at: '2024-01-20T10:00:00Z', last_seen_at: '2024-01-20T12:00:00Z', expires_at: '2024-01-27T10:00:00Z' },
          { id: '2', ip_address: '192.168.1.101', user_agent: 'Firefox/121 on Windows', started_at: '2024-01-19T10:00:00Z', last_seen_at: '2024-01-19T15:00:00Z', expires_at: '2024-01-26T10:00:00Z' },
        ]),
      });
    });
  });

  test('should display sessions tab on profile page', async ({ page }) => {
    await page.goto('/profile');

    // Sessions tab should be visible
    const sessionsTab = page.getByRole('tab', { name: /sessions/i });
    await expect(sessionsTab).toBeVisible();

    // Click sessions tab
    await sessionsTab.click();

    // Should see Active Sessions heading
    await expect(page.getByRole('heading', { name: 'Active Sessions' })).toBeVisible();
  });
});
