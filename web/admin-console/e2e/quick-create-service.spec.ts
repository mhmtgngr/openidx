import { test, expect } from '@playwright/test';

test.describe('Quick Create BrowZer Service', () => {
  test.beforeEach(async ({ page }) => {
    // Mock proxy routes list
    await page.route('**/api/v1/access/routes*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            routes: [
              {
                id: 'route-1',
                name: 'demo-app',
                description: 'Demo application',
                from_url: 'https://demo.localtest.me',
                to_url: 'http://demo-app:8090',
                preserve_host: false,
                require_auth: true,
                allowed_roles: null,
                allowed_groups: null,
                policy_ids: null,
                idle_timeout: 900,
                absolute_timeout: 43200,
                enabled: true,
                priority: 0,
                ziti_enabled: true,
                ziti_service_name: 'openidx-demo-app',
                route_type: 'http',
                remote_host: '',
                remote_port: 0,
                max_risk_score: 100,
                created_at: '2024-01-01T00:00:00Z',
                updated_at: '2024-01-01T00:00:00Z',
              },
            ],
            total: 1,
          }),
        });
      }
    });
  });

  test('should display Quick Create button on proxy routes page', async ({ page }) => {
    await page.goto('/proxy-routes');

    await expect(page.getByRole('button', { name: /quick create/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /add route/i })).toBeVisible();
  });

  test('should open Quick Create dialog', async ({ page }) => {
    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();

    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();
    await expect(page.getByPlaceholder('my-internal-app')).toBeVisible();
    await expect(page.getByPlaceholder('http://internal-app:8080')).toBeVisible();
    await expect(page.getByPlaceholder('browzer.localtest.me')).toBeVisible();
  });

  test('should have Ziti and BrowZer toggles enabled by default', async ({ page }) => {
    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();

    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    // Both toggles should be checked by default
    const zitiSwitch = page.locator('label:has-text("Ziti Network") >> button[role="switch"]');
    const browzerSwitch = page.locator('label:has-text("BrowZer Access") >> button[role="switch"]');

    await expect(zitiSwitch).toHaveAttribute('data-state', 'checked');
    await expect(browzerSwitch).toHaveAttribute('data-state', 'checked');
  });

  test('should create service via quick-create API', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    // Mock quick-create endpoint
    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-route-id',
            name: 'test-app',
            domain: 'test.localtest.me',
            message: 'route created',
            ziti_enabled: true,
            ziti_service_name: 'openidx-test-app',
            browzer_enabled: true,
            note: "For Docker Compose: add 'test.localtest.me' as network alias on browzer-bootstrapper service",
          }),
        });
      }
    });

    await page.goto('/proxy-routes');

    // Open quick create dialog
    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    // Fill the form
    await page.getByPlaceholder('my-internal-app').fill('test-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://test-service:3000');
    await page.getByPlaceholder('browzer.localtest.me').fill('test.localtest.me');

    // Submit
    await page.getByRole('button', { name: /create service/i }).click();

    // Verify success toast
    await expect(page.getByText('Service created').first()).toBeVisible({ timeout: 5000 });

    // Verify the dialog closed
    await expect(page.locator('text=Quick Create BrowZer Service')).not.toBeVisible();

    // Verify request payload
    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).name).toBe('test-app');
    expect((capturedRequest as Record<string, unknown>).target_url).toBe('http://test-service:3000');
    expect((capturedRequest as Record<string, unknown>).domain).toBe('test.localtest.me');
    expect((capturedRequest as Record<string, unknown>).ziti_enabled).toBe(true);
    expect((capturedRequest as Record<string, unknown>).browzer_enabled).toBe(true);
  });

  test('should create service with Ziti only (no BrowZer)', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-route-id',
            name: 'ziti-only-app',
            domain: 'ziti-browzer.localtest.me',
            message: 'route created',
            ziti_enabled: true,
            browzer_enabled: false,
          }),
        });
      }
    });

    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    // Fill the form
    await page.getByPlaceholder('my-internal-app').fill('ziti-only-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://internal:8080');
    await page.getByPlaceholder('browzer.localtest.me').fill('ziti-browzer.localtest.me');

    // Disable BrowZer toggle
    const browzerSwitch = page.locator('label:has-text("BrowZer Access") >> button[role="switch"]');
    await browzerSwitch.click();

    // Submit
    await page.getByRole('button', { name: /create service/i }).click();

    await expect(page.getByText('Service created').first()).toBeVisible({ timeout: 5000 });

    // Verify BrowZer was disabled in request
    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).browzer_enabled).toBe(false);
    expect((capturedRequest as Record<string, unknown>).ziti_enabled).toBe(true);
  });

  test('should enable Ziti when BrowZer is enabled', async ({ page }) => {
    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    const zitiSwitch = page.locator('label:has-text("Ziti Network") >> button[role="switch"]');
    const browzerSwitch = page.locator('label:has-text("BrowZer Access") >> button[role="switch"]');

    // Disable both
    await browzerSwitch.click();
    await zitiSwitch.click();

    // Verify both are unchecked
    await expect(zitiSwitch).toHaveAttribute('data-state', 'unchecked');
    await expect(browzerSwitch).toHaveAttribute('data-state', 'unchecked');

    // Enable BrowZer - should auto-enable Ziti
    await browzerSwitch.click();

    await expect(browzerSwitch).toHaveAttribute('data-state', 'checked');
    await expect(zitiSwitch).toHaveAttribute('data-state', 'checked');
  });

  test('should disable BrowZer when Ziti is disabled', async ({ page }) => {
    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    const zitiSwitch = page.locator('label:has-text("Ziti Network") >> button[role="switch"]');
    const browzerSwitch = page.locator('label:has-text("BrowZer Access") >> button[role="switch"]');

    // Both should be checked
    await expect(zitiSwitch).toHaveAttribute('data-state', 'checked');
    await expect(browzerSwitch).toHaveAttribute('data-state', 'checked');

    // Disable Ziti - should also disable BrowZer
    await zitiSwitch.click();

    await expect(zitiSwitch).toHaveAttribute('data-state', 'unchecked');
    await expect(browzerSwitch).toHaveAttribute('data-state', 'unchecked');
  });

  test('should show error toast on API failure', async ({ page }) => {
    // Mock quick-create to fail
    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'ziti controller unreachable' }),
      });
    });

    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    await page.getByPlaceholder('my-internal-app').fill('fail-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://fail:8080');
    await page.getByPlaceholder('browzer.localtest.me').fill('fail.localtest.me');

    await page.getByRole('button', { name: /create service/i }).click();

    // Verify error toast
    await expect(page.getByText('Failed to create service').first()).toBeVisible({ timeout: 5000 });
  });

  test('should include allowed roles and groups in request', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-route-id',
            name: 'rbac-app',
            domain: 'rbac.localtest.me',
            message: 'route created',
            ziti_enabled: true,
            browzer_enabled: true,
          }),
        });
      }
    });

    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    await page.getByPlaceholder('my-internal-app').fill('rbac-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://rbac:8080');
    await page.getByPlaceholder('browzer.localtest.me').fill('rbac.localtest.me');
    await page.getByPlaceholder('admin, user').fill('admin, developer');
    await page.getByPlaceholder('engineering').fill('devops, platform');

    await page.getByRole('button', { name: /create service/i }).click();

    await expect(page.getByText('Service created').first()).toBeVisible({ timeout: 5000 });

    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).allowed_roles).toEqual(['admin', 'developer']);
    expect((capturedRequest as Record<string, unknown>).allowed_groups).toEqual(['devops', 'platform']);
  });

  test('should require name, target URL, and domain fields', async ({ page }) => {
    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    // Verify all three required fields have the required attribute
    const nameInput = page.getByPlaceholder('my-internal-app');
    const targetInput = page.getByPlaceholder('http://internal-app:8080');
    const domainInput = page.getByPlaceholder('browzer.localtest.me');

    await expect(nameInput).toHaveAttribute('required', '');
    await expect(targetInput).toHaveAttribute('required', '');
    await expect(domainInput).toHaveAttribute('required', '');
  });

  test('should close dialog with Cancel button', async ({ page }) => {
    await page.goto('/proxy-routes');

    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.locator('text=Quick Create BrowZer Service')).toBeVisible();

    await page.getByRole('button', { name: /cancel/i }).click();

    await expect(page.locator('text=Quick Create BrowZer Service')).not.toBeVisible();
  });

  test('should show existing routes alongside quick-create button', async ({ page }) => {
    await page.goto('/proxy-routes');

    // Existing route should be visible
    await expect(page.getByRole('heading', { name: 'demo-app' })).toBeVisible();
    await expect(page.getByText('https://demo.localtest.me')).toBeVisible();

    // Quick create button should be visible
    await expect(page.getByRole('button', { name: /quick create/i })).toBeVisible();

    // Ziti badge should be visible on existing route
    await expect(page.locator('text=Ziti').first()).toBeVisible();
  });
});

test.describe('Quick Create with route list refresh', () => {
  test('should refresh route list after successful quick-create', async ({ page }) => {
    let callCount = 0;

    // Mock routes - return updated list after creation
    await page.route('**/api/v1/access/routes*', async (route) => {
      if (route.request().method() === 'GET') {
        callCount++;
        const routes = [
          {
            id: 'route-1',
            name: 'demo-app',
            description: 'Demo application',
            from_url: 'https://demo.localtest.me',
            to_url: 'http://demo-app:8090',
            preserve_host: false,
            require_auth: true,
            allowed_roles: null,
            allowed_groups: null,
            idle_timeout: 900,
            absolute_timeout: 43200,
            enabled: true,
            priority: 0,
            ziti_enabled: true,
            ziti_service_name: 'openidx-demo-app',
            route_type: 'http',
            max_risk_score: 100,
            created_at: '2024-01-01T00:00:00Z',
            updated_at: '2024-01-01T00:00:00Z',
          },
        ];

        // After quick-create, include the new route
        if (callCount > 1) {
          routes.push({
            id: 'route-new',
            name: 'new-browzer-app',
            description: '',
            from_url: 'https://newbrowzer.localtest.me',
            to_url: 'http://new-app:3000',
            preserve_host: false,
            require_auth: true,
            allowed_roles: null,
            allowed_groups: null,
            idle_timeout: 900,
            absolute_timeout: 43200,
            enabled: true,
            priority: 0,
            ziti_enabled: true,
            ziti_service_name: 'openidx-new-browzer-app',
            route_type: 'http',
            max_risk_score: 100,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        }

        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ routes, total: routes.length }),
        });
      }
    });

    // Mock quick-create endpoint
    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'route-new',
          name: 'new-browzer-app',
          domain: 'newbrowzer.localtest.me',
          message: 'route created',
          ziti_enabled: true,
          ziti_service_name: 'openidx-new-browzer-app',
          browzer_enabled: true,
        }),
      });
    });

    await page.goto('/proxy-routes');
    await expect(page.getByRole('heading', { name: 'demo-app' })).toBeVisible();

    // Quick create a new service
    await page.getByRole('button', { name: /quick create/i }).click();
    await page.getByPlaceholder('my-internal-app').fill('new-browzer-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://new-app:3000');
    await page.getByPlaceholder('browzer.localtest.me').fill('newbrowzer.localtest.me');

    await page.getByRole('button', { name: /create service/i }).click();

    // Verify success
    await expect(page.getByText('Service created').first()).toBeVisible({ timeout: 5000 });

    // New route should appear in the list after refresh
    await expect(page.getByRole('heading', { name: 'new-browzer-app' })).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Quick Create with Path Prefix', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/routes*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ routes: [], total: 0 }),
        });
      }
    });
  });

  test('should show path prefix field in quick create dialog', async ({ page }) => {
    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /quick create/i }).click();
    await expect(page.getByPlaceholder('/demo')).toBeVisible();
  });

  test('should auto-fill domain when path prefix is set', async ({ page }) => {
    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /quick create/i }).click();

    // Type a path prefix
    await page.getByPlaceholder('/demo').fill('/myapp');

    // Domain should auto-fill with browzer.localtest.me
    const domainInput = page.getByPlaceholder('browzer.localtest.me');
    await expect(domainInput).toHaveValue('browzer.localtest.me');
  });

  test('should show path-based routing hint when prefix is set', async ({ page }) => {
    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /quick create/i }).click();

    await page.getByPlaceholder('/demo').fill('/myapp');

    await expect(page.getByText('Path-based routing on shared domain')).toBeVisible();
  });

  test('should include path_prefix in API request', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-route-id',
            name: 'path-app',
            domain: 'browzer.localtest.me',
            path_prefix: '/demo',
            message: 'route created',
            ziti_enabled: true,
            browzer_enabled: true,
            note: 'Path-based BrowZer routing: browzer.localtest.me/demo → router → backend',
          }),
        });
      }
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /quick create/i }).click();

    await page.getByPlaceholder('my-internal-app').fill('path-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://demo-app:8090');
    await page.getByPlaceholder('/demo').fill('/demo');

    await page.getByRole('button', { name: /create service/i }).click();
    await expect(page.getByText('Service created').first()).toBeVisible({ timeout: 5000 });

    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).name).toBe('path-app');
    expect((capturedRequest as Record<string, unknown>).domain).toBe('browzer.localtest.me');
    expect((capturedRequest as Record<string, unknown>).path_prefix).toBe('/demo');
    expect((capturedRequest as Record<string, unknown>).ziti_enabled).toBe(true);
    expect((capturedRequest as Record<string, unknown>).browzer_enabled).toBe(true);
  });

  test('should not include path_prefix when empty', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    await page.route('**/api/v1/access/services/quick-create', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-route-id',
            name: 'vhost-app',
            domain: 'custom.localtest.me',
            message: 'route created',
            ziti_enabled: true,
            browzer_enabled: true,
          }),
        });
      }
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /quick create/i }).click();

    await page.getByPlaceholder('my-internal-app').fill('vhost-app');
    await page.getByPlaceholder('http://internal-app:8080').fill('http://app:8080');
    await page.getByPlaceholder('browzer.localtest.me').fill('custom.localtest.me');

    await page.getByRole('button', { name: /create service/i }).click();
    await expect(page.getByText('Service created').first()).toBeVisible({ timeout: 5000 });

    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).path_prefix).toBeUndefined();
  });
});
