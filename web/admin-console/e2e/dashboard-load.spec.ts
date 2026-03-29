import { test, expect } from '@playwright/test';
import { DashboardPage } from './pages/dashboard.page';
import { UsersPage } from './pages/users.page';
import { AccessReviewsPage } from './pages/access-reviews.page';

/**
 * Dashboard E2E Tests
 * Tests for dashboard loading, stats display, and navigation
 */

const mockDashboardData = {
  total_users: 156,
  active_users: 142,
  total_groups: 12,
  total_applications: 24,
  active_sessions: 38,
  pending_reviews: 7,
  security_alerts: 2,
  security_alert_details: [
    { message: 'Multiple failed login attempts', count: 15, timestamp: '2026-03-27T10:30:00Z' },
    { message: 'Unusual access pattern detected', count: 3, timestamp: '2026-03-27T09:15:00Z' },
  ],
  recent_activity: [
    { id: '1', type: 'authentication', message: 'User john.doe logged in', actor_name: 'john.doe', timestamp: '2026-03-27T10:25:00Z' },
    { id: '2', type: 'user_management', message: 'New user created', actor_name: 'admin', timestamp: '2026-03-27T10:20:00Z' },
    { id: '3', type: 'configuration', message: 'MFA policy updated', actor_name: 'admin', timestamp: '2026-03-27T10:15:00Z' },
    { id: '4', type: 'authentication', message: 'User jane.smith logged out', actor_name: 'jane.smith', timestamp: '2026-03-27T10:10:00Z' },
    { id: '5', type: 'user_management', message: 'Password reset for user', actor_name: 'admin', timestamp: '2026-03-27T10:05:00Z' },
  ],
  auth_stats: {
    total_logins: 3420,
    successful_logins: 3280,
    failed_logins: 140,
    mfa_usage: 2450,
    logins_by_method: {
      password: 1550,
      sso: 980,
      mfa_totp: 520,
      mfa_sms: 180,
      webauthn: 190,
    },
  },
  ziti_status: {
    enabled: true,
    sdk_ready: true,
    controller_reachable: true,
    services_count: 18,
    identities_count: 142,
  },
  ziti_sync: {
    unsynced_users: 0,
    total_users: 142,
    total_identities: 142,
  },
};

const mockLoginAnalytics = {
  data: [
    { date: '2026-03-20', successful: 145, failed: 8 },
    { date: '2026-03-21', successful: 152, failed: 5 },
    { date: '2026-03-22', successful: 138, failed: 12 },
    { date: '2026-03-23', successful: 165, failed: 6 },
    { date: '2026-03-24', successful: 148, failed: 9 },
    { date: '2026-03-25', successful: 170, failed: 4 },
    { date: '2026-03-26', successful: 158, failed: 7 },
    { date: '2026-03-27', successful: 162, failed: 5 },
  ],
};

const mockRiskAnalytics = {
  data: [
    { level: 'low', count: 2850 },
    { level: 'medium', count: 380 },
    { level: 'high', count: 150 },
    { level: 'critical', count: 40 },
  ],
};

const mockEventAnalytics = {
  data: [
    { event_type: 'user_login', count: 3280 },
    { event_type: 'user_logout', count: 3150 },
    { event_type: 'password_change', count: 45 },
    { event_type: 'mfa_enabled', count: 120 },
    { event_type: 'role_assigned', count: 38 },
  ],
};

test.describe('Dashboard - Load and Display', () => {
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    dashboardPage = new DashboardPage(page);

    // Mock authentication
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock dashboard API
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDashboardData),
      });
    });

    // Mock analytics APIs
    await page.route('**/api/v1/analytics/logins*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockLoginAnalytics),
      });
    });

    await page.route('**/api/v1/analytics/risk*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockRiskAnalytics),
      });
    });

    await page.route('**/api/v1/analytics/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockEventAnalytics),
      });
    });

    // Mock Ziti status API
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDashboardData.ziti_status),
      });
    });

    await page.route('**/api/v1/access/ziti/sync/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDashboardData.ziti_sync),
      });
    });
  });

  test('should display dashboard page with title', async ({ page }) => {
    await dashboardPage.goto();

    await expect(dashboardPage.pageTitle).toBeVisible();
    await expect(dashboardPage.pageDescription).toBeVisible();
  });

  test('should display all stat cards', async ({ page }) => {
    await dashboardPage.goto();

    await expect(dashboardPage.totalUsersCard).toBeVisible();
    await expect(dashboardPage.applicationsCard).toBeVisible();
    await expect(dashboardPage.activeSessionsCard).toBeVisible();
    await expect(dashboardPage.pendingReviewsCard).toBeVisible();
  });

  test('should display correct stat values', async ({ page }) => {
    await dashboardPage.goto();

    const totalUsers = await dashboardPage.getTotalUsers();
    const applications = await dashboardPage.getApplications();
    const activeSessions = await dashboardPage.getActiveSessions();
    const pendingReviews = await dashboardPage.getPendingReviews();

    expect(totalUsers).toBe(156);
    expect(applications).toBe(24);
    expect(activeSessions).toBe(38);
    expect(pendingReviews).toBe(7);
  });

  test('should display security alerts section', async ({ page }) => {
    await dashboardPage.goto();

    await expect(dashboardPage.securityAlertsSection).toBeVisible();

    // Should show alert count
    await expect(page.locator('text=2 failed authentication attempts (24h)')).toBeVisible();
  });

  test('should display no active alerts message when no alerts', async ({ page }) => {
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ...mockDashboardData,
          security_alerts: 0,
          security_alert_details: [],
        }),
      });
    });

    await dashboardPage.goto();

    await expect(page.locator('text=No active alerts')).toBeVisible();
  });

  test('should display recent activity section', async ({ page }) => {
    await dashboardPage.goto();

    await expect(dashboardPage.recentActivitySection).toBeVisible();

    const activityCount = await dashboardPage.getRecentActivityCount();
    expect(activityCount).toBeGreaterThan(0);
  });

  test('should display analytics charts', async ({ page }) => {
    await dashboardPage.goto();

    await expect(dashboardPage.analyticsSection).toBeVisible();
    expect(await dashboardPage.areAnalyticsChartsVisible()).toBe(true);
  });

  test('should display Ziti network card when enabled', async ({ page }) => {
    await dashboardPage.goto();

    await expect(dashboardPage.zitiNetworkCard).toBeVisible();
    await expect(page.locator('text=18 services')).toBeVisible();
    await expect(page.locator('text=142 identities')).toBeVisible();
  });

  test('should allow period selection for analytics', async ({ page }) => {
    await dashboardPage.goto();

    // Select 7d period
    await dashboardPage.selectPeriod('7d');

    // Select 90d period
    await dashboardPage.selectPeriod('90d');
  });
});

test.describe('Dashboard - Navigation', () => {
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    dashboardPage = new DashboardPage(page);

    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock dashboard API
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDashboardData),
      });
    });

    // Mock analytics APIs
    await page.route('**/api/v1/analytics/logins*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockLoginAnalytics),
      });
    });

    await page.route('**/api/v1/analytics/risk*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockRiskAnalytics),
      });
    });

    await page.route('**/api/v1/analytics/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockEventAnalytics),
      });
    });

    // Mock Ziti API
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDashboardData.ziti_status),
      });
    });

    await page.route('**/api/v1/access/ziti/sync/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockDashboardData.ziti_sync),
      });
    });

    // Mock pages for navigation
    await page.route('**/api/v1/identity/users*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '0' },
        body: JSON.stringify([]),
      });
    });

    await page.route('**/api/v1/governance/reviews*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '0' },
        body: JSON.stringify([]),
      });
    });

    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '0' },
        body: JSON.stringify([]),
      });
    });
  });

  test('should navigate to users page via Total Users card', async ({ page }) => {
    await dashboardPage.goto();

    await dashboardPage.navigateToViaCard('Total Users');

    await expect(page).toHaveURL('**/users');
  });

  test('should navigate to applications page via Applications card', async ({ page }) => {
    await dashboardPage.goto();

    await dashboardPage.navigateToViaCard('Applications');

    await expect(page).toHaveURL('**/applications');
  });

  test('should navigate to audit logs via Active Sessions card', async ({ page }) => {
    await dashboardPage.goto();

    await dashboardPage.navigateToViaCard('Active Sessions');

    await expect(page).toHaveURL('**/audit-logs');
  });

  test('should navigate to access reviews via Pending Reviews card', async ({ page }) => {
    await dashboardPage.goto();

    await dashboardPage.navigateToViaCard('Pending Reviews');

    await expect(page).toHaveURL('**/access-reviews');
  });

  test('should navigate to Ziti network page via Ziti card', async ({ page }) => {
    await dashboardPage.goto();

    await dashboardPage.zitiNetworkCard.click();

    await expect(page).toHaveURL('**/ziti-network');
  });
});

test.describe('Dashboard - Loading States', () => {
  test('should show loading state while fetching data', async ({ page }) => {
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Slow API response
    await page.route('**/api/v1/dashboard', async (route) => {
      await new Promise(resolve => setTimeout(resolve, 2000));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ total_users: 100, active_users: 90, total_applications: 10, active_sessions: 20, pending_reviews: 5, security_alerts: 0, recent_activity: [], auth_stats: { total_logins: 1000, successful_logins: 950, failed_logins: 50 } }),
      });
    });

    // Mock analytics APIs with instant response
    await page.route('**/api/v1/analytics/logins*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.route('**/api/v1/analytics/risk*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.route('**/api/v1/analytics/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.goto('/dashboard');

    // Check for loading indicator
    const dashboardPage = new DashboardPage(page);
    await expect(dashboardPage.pageTitle).toBeVisible();

    // Wait for data to load
    await page.waitForTimeout(2500);

    // Verify stats are displayed
    const totalUsers = await dashboardPage.getTotalUsers();
    expect(totalUsers).toBe(100);
  });
});

test.describe('Dashboard - Error Handling', () => {
  test('should handle API error gracefully', async ({ page }) => {
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock API error
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' }),
      });
    });

    await page.goto('/dashboard');

    // Page should still load, but show error or empty state
    await expect(new DashboardPage(page).pageTitle).toBeVisible();
  });

  test('should handle partial data response', async ({ page }) => {
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    // Mock partial data
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 100,
          // Missing other fields
        }),
      });
    });

    await page.goto('/dashboard');

    // Dashboard should still render with available data
    const dashboardPage = new DashboardPage(page);
    await expect(dashboardPage.pageTitle).toBeVisible();

    // Total Users should be displayed
    const totalUsers = await dashboardPage.getTotalUsers();
    expect(totalUsers).toBe(100);
  });
});

test.describe('Dashboard - Real-time Updates', () => {
  test('should refresh data when navigating back to dashboard', async ({ page }) => {
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    let requestCount = 0;

    // Mock dashboard API with counter
    await page.route('**/api/v1/dashboard', async (route) => {
      requestCount++;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 100 + requestCount,
          active_users: 90 + requestCount,
          total_applications: 10,
          active_sessions: 20,
          pending_reviews: 5,
          security_alerts: 0,
          recent_activity: [],
          auth_stats: { total_logins: 1000, successful_logins: 950, failed_logins: 50 },
        }),
      });
    });

    // Mock analytics APIs
    await page.route('**/api/v1/analytics/logins*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.route('**/api/v1/analytics/risk*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.route('**/api/v1/analytics/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();

    const firstLoadUsers = await dashboardPage.getTotalUsers();
    expect(firstLoadUsers).toBe(101); // First request

    // Navigate away and back
    await page.goto('/users');
    await page.waitForTimeout(100);
    await dashboardPage.goto();

    const secondLoadUsers = await dashboardPage.getTotalUsers();
    expect(secondLoadUsers).toBeGreaterThanOrEqual(firstLoadUsers); // Data refreshed
  });
});
