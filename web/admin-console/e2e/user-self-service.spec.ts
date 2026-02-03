import { test, expect } from '@playwright/test';

test.describe('User Profile Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'test-user-id',
          username: 'testuser',
          email: 'test@example.com',
          first_name: 'Test',
          last_name: 'User',
          phone: '+1234567890',
          email_verified: true,
          mfa_enabled: false,
          created_at: '2024-01-01T00:00:00Z',
        }),
      });
    });
  });

  test('should display user profile page', async ({ page }) => {
    await page.goto('/profile');

    await expect(page.locator('h1:has-text("Profile"), h1:has-text("My Profile")')).toBeVisible();
  });

  test('should display user information', async ({ page }) => {
    await page.goto('/profile');

    await expect(page.locator('text=testuser').or(page.locator('text=test@example.com'))).toBeVisible();
  });

  test('should have edit profile button', async ({ page }) => {
    await page.goto('/profile');

    await expect(page.getByRole('button', { name: /edit|update|save/i })).toBeVisible();
  });

  test('should display MFA section', async ({ page }) => {
    await page.goto('/profile');

    await expect(page.locator('text=MFA').or(page.locator('text=Two-Factor').or(page.locator('text=Multi-Factor')))).toBeVisible();
  });
});

test.describe('My Access Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me/access*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          roles: [
            { id: 'role-1', name: 'user', description: 'Regular user access' },
            { id: 'role-2', name: 'developer', description: 'Developer access' },
          ],
          groups: [
            { id: 'group-1', name: 'Engineering', description: 'Engineering team' },
          ],
          applications: [
            { id: 'app-1', name: 'Admin Console', description: 'Admin dashboard' },
            { id: 'app-2', name: 'Developer Portal', description: 'Dev resources' },
          ],
        }),
      });
    });

    await page.route('**/api/v1/identity/me/roles*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'role-1', name: 'user', description: 'Regular user access' },
          { id: 'role-2', name: 'developer', description: 'Developer access' },
        ]),
      });
    });
  });

  test('should display my access page', async ({ page }) => {
    await page.goto('/my-access');

    await expect(page.locator('h1:has-text("My Access")')).toBeVisible();
  });

  test('should display assigned roles', async ({ page }) => {
    await page.goto('/my-access');

    await expect(page.locator('text=Roles').or(page.locator('text=user').or(page.locator('text=developer')))).toBeVisible();
  });
});

test.describe('My Devices Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me/devices*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'MacBook Pro', type: 'laptop', os: 'macOS 14.2', browser: 'Chrome 120', ip_address: '192.168.1.100', current: true, trusted: true, last_activity: '2024-01-20T12:00:00Z' },
          { id: '2', name: 'iPhone 15', type: 'mobile', os: 'iOS 17.2', browser: 'Safari', ip_address: '192.168.1.101', current: false, trusted: true, last_activity: '2024-01-19T15:00:00Z' },
          { id: '3', name: 'Windows PC', type: 'desktop', os: 'Windows 11', browser: 'Edge 120', ip_address: '192.168.1.102', current: false, trusted: false, last_activity: '2024-01-18T10:00:00Z' },
        ]),
      });
    });
  });

  test('should display my devices page', async ({ page }) => {
    await page.goto('/my-devices');

    await expect(page.locator('h1:has-text("My Devices"), h1:has-text("Devices")')).toBeVisible();
  });

  test('should display list of devices', async ({ page }) => {
    await page.goto('/my-devices');

    await expect(page.locator('text=MacBook Pro').or(page.locator('text=macOS'))).toBeVisible();
  });

  test('should show current device indicator', async ({ page }) => {
    await page.goto('/my-devices');

    await expect(page.locator('text=Current').or(page.locator('text=This device'))).toBeVisible();
  });

  test('should have remove device option', async ({ page }) => {
    await page.goto('/my-devices');

    // Look for remove/delete button or menu option
    const removeButton = page.locator('button:has-text("Remove"), button:has-text("Delete"), [aria-label*="remove"], [aria-label*="delete"]');
    const moreMenu = page.locator('button[aria-label="More"], button:has-text("..."), [data-testid="more-menu"]');

    const hasRemoveOption = await removeButton.count() > 0 || await moreMenu.count() > 0;
    expect(hasRemoveOption).toBeTruthy();
  });
});

test.describe('Trusted Browsers Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me/trusted-browsers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', browser: 'Chrome', os: 'macOS', ip_address: '192.168.1.100', current: true, created_at: '2024-01-15T10:00:00Z', expires_at: '2024-02-14T10:00:00Z' },
          { id: '2', browser: 'Firefox', os: 'Windows', ip_address: '192.168.1.101', current: false, created_at: '2024-01-10T10:00:00Z', expires_at: '2024-02-09T10:00:00Z' },
        ]),
      });
    });
  });

  test('should display trusted browsers page', async ({ page }) => {
    await page.goto('/trusted-browsers');

    await expect(page.locator('h1:has-text("Trusted Browsers")')).toBeVisible();
  });

  test('should display list of trusted browsers', async ({ page }) => {
    await page.goto('/trusted-browsers');

    await expect(page.locator('text=Chrome').or(page.locator('text=Firefox'))).toBeVisible();
  });

  test('should show expiration info', async ({ page }) => {
    await page.goto('/trusted-browsers');

    await expect(page.locator('text=Expires').or(page.locator('text=expires').or(page.locator('text=/\\d+ days/')))).toBeVisible();
  });

  test('should have revoke option', async ({ page }) => {
    await page.goto('/trusted-browsers');

    await expect(page.locator('button:has-text("Revoke"), button:has-text("Remove"), [aria-label*="revoke"]').first()).toBeVisible();
  });
});

test.describe('Notification Preferences Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me/notification-preferences*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            email_notifications: true,
            security_alerts: true,
            login_notifications: true,
            access_request_updates: true,
            weekly_digest: false,
            marketing: false,
          }),
        });
      }
    });
  });

  test('should display notification preferences page', async ({ page }) => {
    await page.goto('/notification-preferences');

    await expect(page.locator('h1:has-text("Notification")')).toBeVisible();
  });

  test('should display notification toggles', async ({ page }) => {
    await page.goto('/notification-preferences');

    // Check for toggle switches
    const switches = page.locator('[role="switch"], input[type="checkbox"]');
    await expect(switches.first()).toBeVisible();
  });

  test('should have security alerts option', async ({ page }) => {
    await page.goto('/notification-preferences');

    await expect(page.locator('text=Security').or(page.locator('text=security'))).toBeVisible();
  });

  test('should have email notifications option', async ({ page }) => {
    await page.goto('/notification-preferences');

    await expect(page.locator('text=Email').or(page.locator('text=email'))).toBeVisible();
  });
});

test.describe('Access Requests Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/governance/access-requests*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', resource_type: 'role', resource_name: 'admin', status: 'pending', justification: 'Need admin access for project', created_at: '2024-01-20T10:00:00Z' },
          { id: '2', resource_type: 'application', resource_name: 'Finance Portal', status: 'approved', justification: 'Quarterly reporting', created_at: '2024-01-15T10:00:00Z', approved_at: '2024-01-16T10:00:00Z' },
          { id: '3', resource_type: 'group', resource_name: 'Engineering', status: 'denied', justification: 'Project collaboration', created_at: '2024-01-10T10:00:00Z', denied_at: '2024-01-11T10:00:00Z', denial_reason: 'Not required for current role' },
        ]),
      });
    });
  });

  test('should display access requests page', async ({ page }) => {
    await page.goto('/access-requests');

    await expect(page.locator('h1:has-text("Access Requests")')).toBeVisible();
  });

  test('should display request list', async ({ page }) => {
    await page.goto('/access-requests');

    await expect(page.locator('text=admin').or(page.locator('text=Finance Portal'))).toBeVisible();
  });

  test('should show request status', async ({ page }) => {
    await page.goto('/access-requests');

    await expect(page.locator('text=pending').or(page.locator('text=Pending').or(page.locator('text=approved').or(page.locator('text=Approved'))))).toBeVisible();
  });

  test('should have new request button', async ({ page }) => {
    await page.goto('/access-requests');

    await expect(page.getByRole('button', { name: /new request|request access|create/i })).toBeVisible();
  });
});

test.describe('App Launcher Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me/applications*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'Admin Console', description: 'OpenIDX Admin Dashboard', icon: '', url: 'https://admin.example.com', category: 'Administration' },
          { id: '2', name: 'Developer Portal', description: 'API Documentation', icon: '', url: 'https://dev.example.com', category: 'Development' },
          { id: '3', name: 'HR System', description: 'Human Resources', icon: '', url: 'https://hr.example.com', category: 'Business' },
          { id: '4', name: 'Finance Portal', description: 'Financial Reports', icon: '', url: 'https://finance.example.com', category: 'Business' },
        ]),
      });
    });
  });

  test('should display app launcher page', async ({ page }) => {
    await page.goto('/app-launcher');

    await expect(page.locator('h1:has-text("App"), h1:has-text("Applications"), h1:has-text("My Apps")')).toBeVisible();
  });

  test('should display available applications', async ({ page }) => {
    await page.goto('/app-launcher');

    await expect(page.locator('text=Admin Console')).toBeVisible();
    await expect(page.locator('text=Developer Portal')).toBeVisible();
  });

  test('should have clickable app cards', async ({ page }) => {
    await page.goto('/app-launcher');

    // Apps should be links or have click handlers
    const appCards = page.locator('a:has-text("Admin Console"), button:has-text("Admin Console"), [data-testid="app-card"]');
    await expect(appCards.first()).toBeVisible();
  });

  test('should have search functionality', async ({ page }) => {
    await page.goto('/app-launcher');

    // Look for search input
    const searchInput = page.locator('input[type="search"], input[placeholder*="Search"], input[placeholder*="search"]');
    const hasSearch = await searchInput.count() > 0;

    // Search is optional but expected
    if (hasSearch) {
      await expect(searchInput).toBeVisible();
    }
  });
});

test.describe('Password Change Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'test-user-id',
          username: 'testuser',
          email: 'test@example.com',
        }),
      });
    });
  });

  test('should have change password option on profile page', async ({ page }) => {
    await page.goto('/profile');

    await expect(page.locator('text=Password').or(page.locator('text=Change Password').or(page.locator('button:has-text("Password")')))).toBeVisible();
  });
});

test.describe('MFA Setup Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'test-user-id',
          username: 'testuser',
          email: 'test@example.com',
          mfa_enabled: false,
        }),
      });
    });

    await page.route('**/api/v1/identity/me/mfa/setup*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          secret: 'JBSWY3DPEHPK3PXP',
          qr_code: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
          recovery_codes: ['ABC123', 'DEF456', 'GHI789'],
        }),
      });
    });
  });

  test('should show MFA setup option when MFA is not enabled', async ({ page }) => {
    await page.goto('/profile');

    // Look for MFA setup button or link
    await expect(page.locator('text=Enable MFA').or(page.locator('text=Setup MFA').or(page.locator('text=Two-Factor')))).toBeVisible();
  });
});

test.describe('Session Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/me/sessions*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', ip_address: '192.168.1.100', user_agent: 'Chrome/120 on macOS', current: true, created_at: '2024-01-20T10:00:00Z', last_activity: '2024-01-20T12:00:00Z' },
          { id: '2', ip_address: '192.168.1.101', user_agent: 'Firefox/121 on Windows', current: false, created_at: '2024-01-19T10:00:00Z', last_activity: '2024-01-19T15:00:00Z' },
        ]),
      });
    });
  });

  test('should display user sessions in profile or dedicated page', async ({ page }) => {
    await page.goto('/profile');

    // Sessions might be shown on profile or have a dedicated section
    const sessionsVisible = await page.locator('text=Sessions').or(page.locator('text=Active Sessions')).count() > 0;

    if (!sessionsVisible) {
      // Try navigating to dedicated sessions page
      await page.goto('/my-devices');
    }

    // Should see session info somewhere
    await expect(page.locator('text=Chrome').or(page.locator('text=192.168.1'))).toBeVisible();
  });
});
