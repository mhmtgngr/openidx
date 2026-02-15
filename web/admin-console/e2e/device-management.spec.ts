import { test, expect } from '@playwright/test';

test.describe('Unified Device Management', () => {
  test.beforeEach(async ({ page }) => {
    // Mock enriched devices API
    await page.route('**/api/v1/access/devices/enriched*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          devices: [
            {
              id: 'dev-1', fingerprint: 'abc123def456', name: 'Work Laptop',
              ip_address: '192.168.1.10', user_agent: 'Mozilla/5.0 Windows', location: 'New York',
              trusted: true, last_seen_at: '2024-06-01T10:00:00Z', created_at: '2024-01-01T00:00:00Z',
              user_id: 'user-1', username: 'admin', email: 'admin@openidx.io',
              first_name: 'Admin', last_name: 'User',
              ziti_id: 'zi-1', ziti_enrolled: true, ziti_attributes: ['Administrators', 'device-trusted'],
            },
            {
              id: 'dev-2', fingerprint: 'xyz789abc012', name: 'Personal Phone',
              ip_address: '10.0.0.5', user_agent: 'Mozilla/5.0 iPhone Mobile', location: 'London',
              trusted: false, last_seen_at: '2024-06-01T09:00:00Z', created_at: '2024-02-01T00:00:00Z',
              user_id: 'user-2', username: 'jsmith', email: 'jsmith@openidx.io',
              first_name: 'John', last_name: 'Smith',
              ziti_id: 'zi-2', ziti_enrolled: true, ziti_attributes: ['Developers'],
            },
            {
              id: 'dev-3', fingerprint: 'nnn000mmm111', name: 'New Device',
              ip_address: '172.16.0.1', user_agent: 'Mozilla/5.0 Linux', location: 'Berlin',
              trusted: false, last_seen_at: '2024-06-01T08:00:00Z', created_at: '2024-05-01T00:00:00Z',
              user_id: 'user-3', username: 'newuser', email: 'newuser@openidx.io',
              first_name: '', last_name: '',
              ziti_id: '', ziti_enrolled: false, ziti_attributes: [],
            },
          ],
          total: 3,
        }),
      });
    });

    // Mock risk stats
    await page.route('**/api/v1/risk/stats', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_devices: 3,
          trusted_devices: 1,
          new_devices_today: 1,
          high_risk_logins_today: 0,
        }),
      });
    });

    // Mock device trust sync
    await page.route('**/api/v1/access/ziti/sync/device-trust/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'device trust synced' }),
      });
    });
  });

  test('should display enriched devices page with unified columns', async ({ page }) => {
    await page.goto('/devices');
    await expect(page.locator('h1:has-text("Devices")')).toBeVisible();
    await expect(page.getByText('trust status controls network access')).toBeVisible();
  });

  test('should show User column with owner info', async ({ page }) => {
    await page.goto('/devices');
    await expect(page.getByRole('columnheader', { name: 'User' })).toBeVisible();
    await expect(page.getByText('Admin User')).toBeVisible();
    await expect(page.getByText('admin@openidx.io')).toBeVisible();
  });

  test('should show Ziti Status column with enrollment badges', async ({ page }) => {
    await page.goto('/devices');
    await expect(page.getByRole('columnheader', { name: 'Ziti Status' })).toBeVisible();
    // Enrolled devices
    const enrolledBadges = page.getByText('Enrolled', { exact: true });
    await expect(enrolledBadges.first()).toBeVisible();
    // Not linked device
    await expect(page.getByText('Not Linked')).toBeVisible();
  });

  test('should show Network Access column with active/inactive', async ({ page }) => {
    await page.goto('/devices');
    await expect(page.getByRole('columnheader', { name: 'Network Access' })).toBeVisible();
    // Trusted + enrolled = Active
    await expect(page.getByText('Active', { exact: true }).first()).toBeVisible();
    // Untrusted or not enrolled = Inactive
    const inactiveBadges = page.getByText('Inactive', { exact: true });
    await expect(inactiveBadges.first()).toBeVisible();
  });

  test('should show trust status badges', async ({ page }) => {
    await page.goto('/devices');
    await expect(page.getByText('Trusted', { exact: true })).toBeVisible();
    const untrustedBadges = page.getByText('Untrusted', { exact: true });
    await expect(untrustedBadges.first()).toBeVisible();
  });

  test('should have trust and revoke actions in dropdown', async ({ page }) => {
    await page.goto('/devices');
    // Click dropdown on untrusted device
    const rows = page.locator('table tbody tr');
    const untrustedRow = rows.filter({ hasText: 'Personal Phone' });
    await untrustedRow.locator('button').last().click();
    await expect(page.getByText('Trust Device')).toBeVisible();
  });

  test('should trigger Ziti sync on trust action', async ({ page }) => {
    let syncCalled = false;
    await page.route('**/api/v1/devices/dev-2/trust', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Device trusted', user_id: 'user-2' }),
      });
    });
    await page.route('**/api/v1/access/ziti/sync/device-trust/user-2', async (route) => {
      syncCalled = true;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'device trust synced' }),
      });
    });

    await page.goto('/devices');
    const rows = page.locator('table tbody tr');
    const untrustedRow = rows.filter({ hasText: 'Personal Phone' });
    await untrustedRow.locator('button').last().click();
    await page.getByText('Trust Device').click();
    // Wait for sync call
    await page.waitForTimeout(500);
    expect(syncCalled).toBe(true);
  });

  test('should search by username', async ({ page }) => {
    await page.goto('/devices');
    await page.getByPlaceholder('Search by name, IP, user, or fingerprint...').fill('jsmith');
    // Only Personal Phone should be visible
    await expect(page.getByText('Personal Phone')).toBeVisible();
    await expect(page.getByText('Work Laptop')).not.toBeVisible();
  });
});

test.describe('My Devices - Network Access Badges', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/portal/devices', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          devices: [
            { id: 'd1', user_id: 'u1', fingerprint: 'fp1', name: 'My Laptop', device_type: 'desktop', ip_address: '192.168.1.5', trusted: true, created_at: '2024-01-01T00:00:00Z', last_seen_at: '2024-06-01T00:00:00Z' },
            { id: 'd2', user_id: 'u1', fingerprint: 'fp2', name: 'My Phone', device_type: 'mobile', ip_address: '10.0.0.1', trusted: false, created_at: '2024-03-01T00:00:00Z', last_seen_at: '2024-05-01T00:00:00Z' },
          ],
        }),
      });
    });
    await page.route('**/api/v1/access/ziti/sync/my-identity', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          linked: true, ziti_id: 'zi-1', name: 'user-identity', enrolled: true,
          attributes: ['Administrators', 'device-trusted'],
        }),
      });
    });
  });

  test('should show Network Active badge on trusted device', async ({ page }) => {
    await page.goto('/my-devices');
    const laptopCard = page.locator('div').filter({ hasText: 'My Laptop' }).first();
    await expect(laptopCard.getByText('Network Active')).toBeVisible();
  });

  test('should show No Network Access on untrusted device', async ({ page }) => {
    await page.goto('/my-devices');
    await expect(page.getByText('No Network Access')).toBeVisible();
  });

  test('should show Ziti identity card', async ({ page }) => {
    await page.goto('/my-devices');
    await expect(page.getByText('Zero Trust Network Identity')).toBeVisible();
    await expect(page.getByText('user-identity')).toBeVisible();
  });
});

test.describe('Device Trust Approval - Ziti Integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/device-trust-requests?*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          requests: [
            { id: 'req-1', user_id: 'user-2', user_email: 'jsmith@openidx.io', user_name: 'John Smith', device_name: 'Work Laptop', device_type: 'desktop', ip_address: '192.168.1.10', justification: 'Need for daily work', status: 'pending', created_at: '2024-06-01T00:00:00Z' },
          ],
          total: 1,
        }),
      });
    });
    await page.route('**/api/v1/identity/device-trust-requests/pending-count', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ count: 1 }),
      });
    });
    await page.route('**/api/v1/identity/device-trust-settings', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ id: 's1', require_approval: true, auto_approve_known_ips: false, auto_approve_corporate_devices: false, request_expiry_hours: 72, notify_admins: true, notify_user_on_decision: true }),
      });
    });
  });

  test('should show network access note in approval dialog', async ({ page }) => {
    await page.goto('/device-trust-approval');
    // Click approve button on the request
    await page.locator('button').filter({ hasText: /^$/ }).first(); // Approve icon button
    const approveBtn = page.getByRole('row').filter({ hasText: 'John Smith' }).getByRole('button').first();
    await approveBtn.click();
    await expect(page.getByText('device-trusted')).toBeVisible();
  });
});
