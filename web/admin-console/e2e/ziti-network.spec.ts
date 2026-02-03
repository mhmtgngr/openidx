import { test, expect } from '@playwright/test';

test.describe('Ziti Network Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock Ziti status API
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          sdk_ready: true,
          controller_reachable: true,
          services_count: 5,
          identities_count: 10,
        }),
      });
    });

    // Mock fabric overview
    await page.route('**/api/v1/access/ziti/fabric/overview', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          controller_online: true,
          router_count: 3,
          service_count: 5,
          identity_count: 10,
          healthy_routers: 2,
          unhealthy_routers: 1,
        }),
      });
    });

    // Mock fabric routers
    await page.route('**/api/v1/access/ziti/fabric/routers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'router-1', name: 'edge-router-1', is_online: true, hostname: 'router1.example.com', fingerprint: 'abc123def456', created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-20T00:00:00Z' },
          { id: 'router-2', name: 'edge-router-2', is_online: true, hostname: 'router2.example.com', fingerprint: 'xyz789uvw012', created_at: '2024-01-05T00:00:00Z', updated_at: '2024-01-20T00:00:00Z' },
          { id: 'router-3', name: 'edge-router-3', is_online: false, hostname: 'router3.example.com', fingerprint: 'mno345pqr678', created_at: '2024-01-10T00:00:00Z', updated_at: '2024-01-15T00:00:00Z' },
        ]),
      });
    });

    // Mock services
    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'svc-003', name: 'database', description: 'PostgreSQL', protocol: 'tcp', host: '10.0.0.3', port: 5432, enabled: false, created_at: '2024-01-10T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-service-id',
            ziti_id: 'svc-new',
            ...body,
            enabled: true,
            created_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock identities
    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            identities: [
              { id: '1', ziti_id: 'id-001', name: 'user-john', identity_type: 'User', user_id: 'user-1', enrolled: true, attributes: ['users', 'developers'], created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'id-002', name: 'device-laptop', identity_type: 'Device', enrolled: true, attributes: ['devices', 'trusted'], created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'id-003', name: 'service-api', identity_type: 'Service', enrolled: false, attributes: ['services'], created_at: '2024-01-10T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-identity-id',
            ziti_id: 'id-new',
            ...body,
            enrolled: false,
            created_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock identity enrollment JWT
    await page.route('**/api/v1/access/ziti/identities/*/enrollment-jwt', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jwt: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock-enrollment-jwt-content.signature',
        }),
      });
    });

    // Mock delete endpoints
    await page.route('**/api/v1/access/ziti/services/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      }
    });

    await page.route('**/api/v1/access/ziti/identities/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      }
    });
  });

  test('should display Ziti Network page', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('h1:has-text("Ziti Network")')).toBeVisible();
    await expect(page.locator('text=Manage your OpenZiti zero-trust network overlay')).toBeVisible();
  });

  test('should show connection status', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=Connected')).toBeVisible();
  });

  test('should display services and identities count badges', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=5 services')).toBeVisible();
    await expect(page.locator('text=10 identities')).toBeVisible();
  });

  test('should have all navigation tabs', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('tab', { name: /overview/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /services/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /identities/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /security/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /remote access/i })).toBeVisible();
  });
});

test.describe('Ziti Overview Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 5, identities_count: 10 }),
      });
    });

    await page.route('**/api/v1/access/ziti/fabric/overview', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ controller_online: true, router_count: 3, service_count: 5, identity_count: 10, healthy_routers: 2, unhealthy_routers: 1 }),
      });
    });

    await page.route('**/api/v1/access/ziti/fabric/routers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'edge-router-1', is_online: true, hostname: 'router1.example.com', fingerprint: 'abc123', created_at: '2024-01-01T00:00:00Z' },
          { id: '2', name: 'edge-router-2', is_online: false, hostname: 'router2.example.com', fingerprint: 'def456', created_at: '2024-01-05T00:00:00Z' },
        ]),
      });
    });
  });

  test('should display controller status', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=Controller')).toBeVisible();
    await expect(page.locator('text=Online').first()).toBeVisible();
  });

  test('should display router count', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=Routers')).toBeVisible();
    await expect(page.locator('text=2 healthy, 1 unhealthy')).toBeVisible();
  });

  test('should display edge routers table', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.locator('text=Edge Routers')).toBeVisible();
    await expect(page.locator('text=edge-router-1')).toBeVisible();
    await expect(page.locator('text=edge-router-2')).toBeVisible();
  });

  test('should show router online/offline status', async ({ page }) => {
    await page.goto('/ziti-network');

    // Check for Online badge
    await expect(page.locator('td >> text=Online').first()).toBeVisible();
    // Check for Offline badge
    await expect(page.locator('td >> text=Offline')).toBeVisible();
  });

  test('should have health check button', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('button', { name: /health check/i })).toBeVisible();
  });

  test('should have reconnect button', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('button', { name: /reconnect/i })).toBeVisible();
  });
});

test.describe('Ziti Services Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 3, identities_count: 5 }) });
    });

    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'new', ziti_id: 'svc-new', name: 'new-service', created_at: new Date().toISOString() }) });
      }
    });

    await page.route('**/api/v1/access/ziti/services/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 204 });
      }
    });
  });

  test('should display services tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.locator('text=web-service')).toBeVisible();
    await expect(page.locator('text=api-service')).toBeVisible();
  });

  test('should have Add Service button', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.getByRole('button', { name: /add service/i })).toBeVisible();
  });

  test('should open create service modal', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    await expect(page.locator('text=Create Ziti Service')).toBeVisible();
    await expect(page.getByLabel(/service name/i)).toBeVisible();
    await expect(page.getByLabel(/host/i)).toBeVisible();
    await expect(page.getByLabel(/port/i)).toBeVisible();
  });

  test('should create service successfully', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    await page.getByLabel(/service name/i).fill('new-service');
    await page.getByLabel(/host/i).fill('192.168.1.100');
    await page.getByLabel(/port/i).fill('3000');

    await page.getByRole('button', { name: /create/i }).click();

    // Success toast
    await expect(page.locator('text=Service created').first()).toBeVisible();
  });

  test('should have search input for services', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.getByPlaceholder(/search services/i)).toBeVisible();
  });

  test('should show service details', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    // Check service info is displayed
    await expect(page.locator('text=10.0.0.1').or(page.locator('text=443'))).toBeVisible();
  });
});

test.describe('Ziti Identities Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 3, identities_count: 3 }) });
    });

    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            identities: [
              { id: '1', ziti_id: 'id-001', name: 'user-john', identity_type: 'User', user_id: 'user-1', enrolled: true, attributes: ['users'], created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'id-002', name: 'device-laptop', identity_type: 'Device', enrolled: true, attributes: ['devices'], created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'id-003', name: 'service-api', identity_type: 'Service', enrolled: false, attributes: ['services'], created_at: '2024-01-10T00:00:00Z' },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 'new', ziti_id: 'id-new', name: 'new-identity', enrolled: false, created_at: new Date().toISOString() }) });
      }
    });

    await page.route('**/api/v1/access/ziti/identities/*/enrollment-jwt', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ jwt: 'mock-enrollment-jwt' }) });
    });
  });

  test('should display identities tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.locator('text=user-john')).toBeVisible();
    await expect(page.locator('text=device-laptop')).toBeVisible();
    await expect(page.locator('text=service-api')).toBeVisible();
  });

  test('should show identity types', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Check that at least one identity type is visible in the table
    await expect(page.locator('td:has-text("User")').or(page.locator('td:has-text("Device")').or(page.locator('td:has-text("Service")'))).first()).toBeVisible();
  });

  test('should have Add Identity button', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.getByRole('button', { name: /add identity/i })).toBeVisible();
  });

  test('should open create identity modal', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await page.getByRole('button', { name: /add identity/i }).click();

    await expect(page.locator('text=Create Ziti Identity')).toBeVisible();
    await expect(page.getByLabel(/identity name/i)).toBeVisible();
  });

  test('should show enrollment status', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Check for enrolled/not enrolled indicators
    await expect(page.locator('text=Enrolled').or(page.locator('text=Not Enrolled').or(page.locator('text=Pending')))).toBeVisible();
  });

  test('should have search input for identities', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.getByPlaceholder(/search identities/i)).toBeVisible();
  });
});

test.describe('Ziti Network Status Conditions', () => {
  test('should show disconnected status when controller is unreachable', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          sdk_ready: false,
          controller_reachable: false,
          controller_error: 'Connection refused',
          services_count: 0,
          identities_count: 0,
        }),
      });
    });

    await page.goto('/ziti-network');

    await expect(page.locator('text=Disconnected')).toBeVisible();
  });

  test('should show empty state when no services exist', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 0, identities_count: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/services', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ services: [] }) });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await expect(page.locator('text=No services').or(page.locator('text=No Ziti services'))).toBeVisible();
  });

  test('should show empty state when no identities exist', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 0, identities_count: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/identities', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ identities: [] }) });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    await expect(page.locator('text=No identities').or(page.locator('text=No Ziti identities'))).toBeVisible();
  });

  test('should show empty state when no routers exist', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 0, identities_count: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/fabric/overview', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ controller_online: true, router_count: 0, service_count: 0, identity_count: 0, healthy_routers: 0, unhealthy_routers: 0 }) });
    });

    await page.route('**/api/v1/access/ziti/fabric/routers', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([]) });
    });

    await page.goto('/ziti-network');

    await expect(page.locator('text=No edge routers')).toBeVisible();
  });
});

test.describe('Ziti Security Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 5, identities_count: 10 }) });
    });

    await page.route('**/api/v1/access/ziti/posture-checks*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          checks: [
            { id: '1', name: 'OS Check', check_type: 'os', enabled: true, severity: 'high', created_at: '2024-01-01T00:00:00Z' },
            { id: '2', name: 'MFA Check', check_type: 'mfa', enabled: true, severity: 'critical', created_at: '2024-01-05T00:00:00Z' },
          ],
          summary: { total_checks: 2, enabled_checks: 2, disabled_checks: 0, by_type: { os: 1, mfa: 1 }, by_severity: { high: 1, critical: 1 } },
        }),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'Root CA', cert_type: 'ca', subject: 'CN=Root CA', issuer: 'CN=Root CA', fingerprint: 'abc123', not_before: '2024-01-01', not_after: '2026-01-01', auto_renew: true, status: 'valid', days_until_expiry: 365 },
        ]),
      });
    });
  });

  test('should display security tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // Check for posture checks section
    await expect(page.locator('text=Posture Checks').or(page.locator('text=Security Policies'))).toBeVisible();
  });

  test('should show posture checks', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    await expect(page.locator('text=OS Check').or(page.locator('text=MFA Check'))).toBeVisible();
  });

  test('should show certificates section', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    await expect(page.locator('text=Certificates').or(page.locator('text=Root CA'))).toBeVisible();
  });
});

test.describe('Ziti Remote Access Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true, services_count: 5, identities_count: 10 }) });
    });

    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.example.com',
        }),
      });
    });

    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', route_id: 'route-1', protocol: 'ssh', hostname: 'server1.example.com', port: 22, created_at: '2024-01-01T00:00:00Z' },
          { id: '2', route_id: 'route-2', protocol: 'rdp', hostname: 'server2.example.com', port: 3389, created_at: '2024-01-05T00:00:00Z' },
        ]),
      });
    });
  });

  test('should display remote access tab content', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    await expect(page.getByRole('heading', { name: 'BrowZer' }).or(page.locator('text=Remote Access').first())).toBeVisible();
  });

  test('should show BrowZer status', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    await expect(page.getByRole('heading', { name: 'BrowZer' })).toBeVisible();
  });
});
