import { test, expect } from '@playwright/test';

const mockApps = [
  {
    id: 'app-001',
    name: 'HR Portal',
    description: 'Employee management system',
    target_url: 'http://hr-app:8080',
    spec_url: '',
    status: 'discovered',
    discovery_started_at: '2025-01-01T00:00:00Z',
    discovery_completed_at: '2025-01-01T00:00:10Z',
    discovery_error: null,
    discovery_strategies: ['probe', 'html_crawl'],
    total_paths_discovered: 5,
    total_paths_published: 1,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:10Z',
  },
];

const mockPaths = [
  {
    id: 'path-001',
    app_id: 'app-001',
    path: '/admin',
    http_methods: ['GET'],
    classification: 'critical',
    classification_source: 'auto',
    discovery_strategy: 'probe',
    suggested_policy: 'admin + device trust',
    require_auth: true,
    allowed_roles: ['admin'],
    require_device_trust: true,
    published: false,
    route_id: null,
    metadata: {},
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  },
  {
    id: 'path-002',
    app_id: 'app-001',
    path: '/api/users',
    http_methods: ['GET', 'POST'],
    classification: 'sensitive',
    classification_source: 'auto',
    discovery_strategy: 'probe',
    suggested_policy: 'admin only',
    require_auth: true,
    allowed_roles: ['admin'],
    require_device_trust: false,
    published: false,
    route_id: null,
    metadata: {},
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  },
  {
    id: 'path-003',
    app_id: 'app-001',
    path: '/dashboard',
    http_methods: ['GET'],
    classification: 'protected',
    classification_source: 'auto',
    discovery_strategy: 'html_crawl',
    suggested_policy: 'authenticated users',
    require_auth: true,
    allowed_roles: [],
    require_device_trust: false,
    published: false,
    route_id: null,
    metadata: {},
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  },
  {
    id: 'path-004',
    app_id: 'app-001',
    path: '/health',
    http_methods: ['GET'],
    classification: 'public',
    classification_source: 'auto',
    discovery_strategy: 'probe',
    suggested_policy: 'no auth',
    require_auth: false,
    allowed_roles: [],
    require_device_trust: false,
    published: false,
    route_id: null,
    metadata: {},
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  },
  {
    id: 'path-005',
    app_id: 'app-001',
    path: '/login',
    http_methods: ['GET', 'POST'],
    classification: 'public',
    classification_source: 'auto',
    discovery_strategy: 'probe',
    suggested_policy: 'no auth',
    require_auth: false,
    allowed_roles: [],
    require_device_trust: false,
    published: true,
    route_id: 'route-001',
    metadata: {},
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  },
];

test.describe('App Publish Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock list apps
    await page.route('**/api/v1/access/apps', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ apps: mockApps, total: mockApps.length }),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'app-new',
            ...body,
            status: 'pending',
            discovery_strategies: [],
            total_paths_discovered: 0,
            total_paths_published: 0,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock single app GET
    await page.route('**/api/v1/access/apps/app-001', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockApps[0]),
        });
      } else if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
      }
    });

    // Mock discover
    await page.route('**/api/v1/access/apps/app-001/discover', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockApps[0], status: 'discovering' }),
      });
    });

    // Mock paths
    await page.route('**/api/v1/access/apps/app-001/paths', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ paths: mockPaths, total: mockPaths.length }),
      });
    });

    // Mock update classification
    await page.route('**/api/v1/access/apps/app-001/paths/path-*', async (route) => {
      if (route.request().method() === 'PUT') {
        const body = route.request().postDataJSON();
        const pathId = route.request().url().split('/').pop();
        const original = mockPaths.find((p) => p.id === pathId) || mockPaths[0];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ...original, ...body, classification_source: 'manual' }),
        });
      }
    });

    // Mock publish
    await page.route('**/api/v1/access/apps/app-001/publish', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ published_count: 2, routes_created: 2 }),
      });
    });

    await page.goto('/app-publish');
  });

  test('displays page header and tabs', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'App Publish' })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Apps/ })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Discovered Paths/ })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Published/ })).toBeVisible();
  });

  test('shows registered apps on the Apps tab', async ({ page }) => {
    await expect(page.getByText('HR Portal')).toBeVisible();
    await expect(page.getByText('http://hr-app:8080')).toBeVisible();
    await expect(page.getByText('discovered', { exact: true })).toBeVisible();
    await expect(page.getByText('5 discovered')).toBeVisible();
    await expect(page.getByText('1 published')).toBeVisible();
    // Discovery strategies
    await expect(page.getByText('probe')).toBeVisible();
    await expect(page.getByText('html_crawl')).toBeVisible();
  });

  test('opens register app dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Register App' }).click();
    await expect(page.getByRole('heading', { name: 'Register Application' })).toBeVisible();
    await expect(page.getByLabel('Name')).toBeVisible();
    await expect(page.getByLabel('Target URL')).toBeVisible();
    await expect(page.getByLabel(/OpenAPI Spec URL/)).toBeVisible();
    await expect(page.getByLabel(/Description/)).toBeVisible();
  });

  test('registers a new app', async ({ page }) => {
    await page.getByRole('button', { name: 'Register App' }).click();
    await page.getByLabel('Name').fill('Test App');
    await page.getByLabel('Target URL').fill('http://test-app:3000');
    await page.getByRole('button', { name: 'Register' }).click();
    // Toast should appear
    await expect(page.getByText('App Registered').first()).toBeVisible();
  });

  test('navigates to discovered paths tab', async ({ page }) => {
    // Click the Paths button on the app card
    await page.getByRole('button', { name: 'Paths' }).click();
    // Should switch to paths tab
    await expect(page.getByText('Total')).toBeVisible();
    // Verify classification summary cards
    await expect(page.getByText('critical').first()).toBeVisible();
    await expect(page.getByText('sensitive').first()).toBeVisible();
  });

  test('shows discovered paths table', async ({ page }) => {
    await page.getByRole('button', { name: 'Paths' }).click();
    // Verify paths in table
    await expect(page.getByText('/admin')).toBeVisible();
    await expect(page.getByText('/api/users')).toBeVisible();
    await expect(page.getByText('/dashboard')).toBeVisible();
    await expect(page.getByText('/health')).toBeVisible();
    await expect(page.getByText('/login')).toBeVisible();
  });

  test('shows published paths on Published tab', async ({ page }) => {
    // Navigate to paths first to select the app
    await page.getByRole('button', { name: 'Paths' }).click();
    // Switch to Published tab
    await page.getByRole('tab', { name: /Published/ }).click();
    // /login is the only published path
    await expect(page.getByText('/login')).toBeVisible();
    await expect(page.getByText('View Route')).toBeVisible();
  });

  test('search filters paths', async ({ page }) => {
    await page.getByRole('button', { name: 'Paths' }).click();
    await page.getByPlaceholder('Search paths...').fill('/admin');
    // Only /admin should be visible
    await expect(page.getByText('/admin')).toBeVisible();
    await expect(page.getByText('/api/users')).not.toBeVisible();
    await expect(page.getByText('/dashboard')).not.toBeVisible();
  });

  test('can select paths and open publish dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Paths' }).click();

    // Radix Checkbox uses <button role="checkbox">. Select first in body rows.
    const checkboxes = page.locator('tbody button[role="checkbox"]').filter({ hasNot: page.locator('[disabled]') });
    await checkboxes.first().click();

    // The publish button should show count
    await expect(page.getByRole('button', { name: /Publish Selected \(1\)/ })).toBeVisible();

    // Open publish dialog
    await page.getByRole('button', { name: /Publish Selected/ }).click();
    await expect(page.getByRole('heading', { name: 'Publish Selected Paths' })).toBeVisible();
    await expect(page.getByText('OpenZiti zero-trust overlay')).toBeVisible();
    await expect(page.getByText('BrowZer clientless access')).toBeVisible();
  });

  test('Discover button exists on app card', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Discover' })).toBeVisible();
  });

  test('empty state shows message when no apps', async ({ page }) => {
    // Override the route to return empty
    await page.route('**/api/v1/access/apps', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ apps: [], total: 0 }),
        });
      }
    });
    await page.goto('/app-publish');
    await expect(page.getByText('No apps registered yet')).toBeVisible();
  });
});
