import { test, expect } from '@playwright/test';

const mockRoute = {
  id: 'route-1',
  name: 'demo-app',
  description: 'Demo application',
  from_url: 'http://browzer.localtest.me/demo',
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
};

const mockSshRoute = {
  ...mockRoute,
  id: 'route-2',
  name: 'ssh-server',
  description: 'SSH access',
  from_url: 'ssh://192.168.1.100',
  to_url: '',
  route_type: 'ssh',
  remote_host: '192.168.1.100',
  remote_port: 22,
  ziti_enabled: false,
  ziti_service_name: '',
};

const mockServiceStatus = (features: Record<string, object>) => ({
  route_id: 'route-1',
  route_name: 'demo-app',
  route_type: 'http',
  features,
  overall_health: 'healthy',
});

test.describe('Service Feature Panel', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/routes*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ routes: [mockRoute], total: 1 }),
        });
      }
    });
  });

  test('should show Features button on each route card', async ({ page }) => {
    await page.goto('/proxy-routes');
    await expect(page.getByRole('button', { name: /Features/ })).toBeVisible();
  });

  test('should show Test Connection button on each route card', async ({ page }) => {
    await page.goto('/proxy-routes');
    await expect(page.getByRole('button', { name: /Test Connection/ })).toBeVisible();
  });

  test('should expand feature panel when Features is clicked', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: true, status: 'enabled', health_status: 'healthy',
          },
          browzer: {
            id: 'f-2', route_id: 'route-1', feature_name: 'browzer',
            enabled: true, status: 'enabled', health_status: 'healthy',
          },
        })),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    await expect(page.getByText('OpenZiti Zero Trust')).toBeVisible();
    await expect(page.locator('.font-medium').getByText('BrowZer', { exact: true })).toBeVisible();
    await expect(page.getByText('Enable or disable integration features')).toBeVisible();
  });

  test('should collapse feature panel when Features is clicked again', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: false, status: 'disabled', health_status: 'unknown',
          },
        })),
      });
    });

    await page.goto('/proxy-routes');

    // Expand
    await page.getByRole('button', { name: /Features/ }).click();
    await expect(page.getByText('OpenZiti Zero Trust')).toBeVisible();

    // Collapse
    await page.getByRole('button', { name: /Features/ }).click();
    await expect(page.getByText('OpenZiti Zero Trust')).not.toBeVisible();
  });

  test('should show health badges for enabled features', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: true, status: 'enabled', health_status: 'healthy',
          },
          browzer: {
            id: 'f-2', route_id: 'route-1', feature_name: 'browzer',
            enabled: true, status: 'enabled', health_status: 'degraded',
          },
        })),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    await expect(page.getByText('Healthy').first()).toBeVisible();
    await expect(page.getByText('Degraded')).toBeVisible();
  });

  test('should open Ziti config modal when enabling Ziti', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: false, status: 'disabled', health_status: 'unknown',
          },
        })),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    // Click Ziti toggle (currently off)
    const zitiSwitch = page.locator('div:has-text("OpenZiti Zero Trust") >> button[role="switch"]').first();
    await zitiSwitch.click();

    // Config modal should open
    await expect(page.getByText('Configure OpenZiti')).toBeVisible();
    await expect(page.getByPlaceholder('Auto-generated if empty')).toBeVisible();
    await expect(page.getByPlaceholder("Uses route's remote_host if empty")).toBeVisible();
    await expect(page.getByPlaceholder("Uses route's remote_port if empty")).toBeVisible();
  });

  test('should enable Ziti with config', async ({ page }) => {
    let capturedRequest: string | null = null;

    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: false, status: 'disabled', health_status: 'unknown',
          },
        })),
      });
    });

    await page.route('**/api/v1/access/services/route-1/features/ziti/enable', async (route) => {
      capturedRequest = route.request().method();
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    // Toggle Ziti on
    const zitiSwitch = page.locator('div:has-text("OpenZiti Zero Trust") >> button[role="switch"]').first();
    await zitiSwitch.click();

    await expect(page.getByText('Configure OpenZiti')).toBeVisible();

    // Fill config
    await page.getByPlaceholder('Auto-generated if empty').fill('my-ziti-svc');

    // Submit
    await page.getByRole('button', { name: 'Enable' }).click();

    await expect(page.getByText('Feature Enabled').first()).toBeVisible({ timeout: 5000 });
    expect(capturedRequest).toBe('POST');
  });

  test('should disable Ziti feature', async ({ page }) => {
    let disableCalled = false;

    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: true, status: 'enabled', health_status: 'healthy',
          },
        })),
      });
    });

    await page.route('**/api/v1/access/services/route-1/features/ziti/disable', async (route) => {
      disableCalled = true;
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    // Toggle Ziti off
    const zitiSwitch = page.locator('div:has-text("OpenZiti Zero Trust") >> button[role="switch"]').first();
    await zitiSwitch.click();

    await expect(page.getByText('Feature Disabled').first()).toBeVisible({ timeout: 5000 });
    expect(disableCalled).toBe(true);
  });

  test('should disable BrowZer toggle when Ziti is off', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: false, status: 'disabled', health_status: 'unknown',
          },
          browzer: {
            id: 'f-2', route_id: 'route-1', feature_name: 'browzer',
            enabled: false, status: 'disabled', health_status: 'unknown',
          },
        })),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    // BrowZer toggle should be disabled (Ziti required)
    const browzerRow = page.locator('[class*="justify-between"]', { hasText: 'BrowZer' })
      .filter({ hasText: 'browser-native' });
    const browzerSwitch = browzerRow.locator('button[role="switch"]');
    await expect(browzerSwitch).toBeDisabled();
  });

  test('should show error message for failed features', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockServiceStatus({
          ziti: {
            id: 'f-1', route_id: 'route-1', feature_name: 'ziti',
            enabled: true, status: 'error', health_status: 'unhealthy',
            error_message: 'Ziti controller connection timeout',
          },
        })),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    await expect(page.getByText('Ziti controller connection timeout')).toBeVisible();
    await expect(page.getByText('Unhealthy')).toBeVisible();
  });
});

test.describe('Service Feature Panel - SSH Route with Guacamole', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/routes*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ routes: [mockSshRoute], total: 1 }),
        });
      }
    });
  });

  test('should show Guacamole option for SSH route type', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-2/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          route_id: 'route-2',
          route_name: 'ssh-server',
          route_type: 'ssh',
          features: {
            ziti: {
              id: 'f-1', route_id: 'route-2', feature_name: 'ziti',
              enabled: false, status: 'disabled', health_status: 'unknown',
            },
            guacamole: {
              id: 'f-3', route_id: 'route-2', feature_name: 'guacamole',
              enabled: false, status: 'disabled', health_status: 'unknown',
            },
          },
          overall_health: 'unknown',
        }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    await expect(page.getByText('Guacamole Remote Access')).toBeVisible();
    await expect(page.getByText('Clientless SSH access through browser')).toBeVisible();
  });

  test('should open Guacamole config modal when enabling', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-2/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          route_id: 'route-2',
          route_name: 'ssh-server',
          route_type: 'ssh',
          features: {
            guacamole: {
              id: 'f-3', route_id: 'route-2', feature_name: 'guacamole',
              enabled: false, status: 'disabled', health_status: 'unknown',
            },
          },
          overall_health: 'unknown',
        }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Features/ }).click();

    const guacRow = page.locator('[class*="justify-between"]', { hasText: 'Guacamole Remote Access' });
    const guacSwitch = guacRow.locator('button[role="switch"]');
    await guacSwitch.click();

    await expect(page.getByText('Configure Guacamole')).toBeVisible();
    await expect(page.getByPlaceholder('ssh, rdp, vnc, telnet')).toBeVisible();
  });
});

test.describe('Connection Test Button', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/routes*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ routes: [mockRoute], total: 1 }),
        });
      }
    });
  });

  test('should show test results dialog on success', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/test-connection', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          tests: {
            upstream_reachable: {
              success: true,
              latency_ms: 12,
              status_code: 200,
            },
            dns_resolution: {
              success: true,
              latency_ms: 3,
            },
          },
          overall_latency_ms: 15,
          tested_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Test Connection/ }).click();

    // Wait for results dialog
    await expect(page.getByText('Connection Test Results')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Total Time')).toBeVisible();
    await expect(page.getByText('15ms').first()).toBeVisible();

    // Individual test results
    await expect(page.getByText('upstream reachable')).toBeVisible();
    await expect(page.getByText('dns resolution')).toBeVisible();
    await expect(page.getByText('Pass').first()).toBeVisible();
  });

  test('should show failed test results', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/test-connection', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: false,
          tests: {
            upstream_reachable: {
              success: false,
              latency_ms: 5000,
              error_message: 'Connection refused: demo-app:8090',
            },
          },
          overall_latency_ms: 5000,
          tested_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Test Connection/ }).click();

    await expect(page.getByText('Connection Test Results')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Fail', { exact: true })).toBeVisible();
    await expect(page.getByText('Connection refused: demo-app:8090')).toBeVisible();
  });

  test('should show success toast on passing test', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/test-connection', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          tests: { basic: { success: true, latency_ms: 5 } },
          overall_latency_ms: 5,
          tested_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Test Connection/ }).click();

    await expect(page.getByText('Connection Test Passed').first()).toBeVisible({ timeout: 10000 });
  });

  test('should show error toast on test failure', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/test-connection', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: false,
          tests: { basic: { success: false, latency_ms: 100, error_message: 'timeout' } },
          overall_latency_ms: 100,
          tested_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Test Connection/ }).click();

    await expect(page.getByText('Connection Test Failed').first()).toBeVisible({ timeout: 10000 });
  });

  test('should show error toast on API error', async ({ page }) => {
    await page.route('**/api/v1/access/services/route-1/test-connection', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' }),
      });
    });

    await page.goto('/proxy-routes');
    await page.getByRole('button', { name: /Test Connection/ }).click();

    await expect(page.getByText('Test Error').first()).toBeVisible({ timeout: 10000 });
  });
});
