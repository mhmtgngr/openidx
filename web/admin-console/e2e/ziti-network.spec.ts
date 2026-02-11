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

    await expect(page.getByRole('heading', { name: 'Routers', exact: true })).toBeVisible();
    await expect(page.locator('text=2 healthy, 1 unhealthy')).toBeVisible();
  });

  test('should display edge routers table', async ({ page }) => {
    await page.goto('/ziti-network');

    await expect(page.getByRole('heading', { name: 'Edge Routers', exact: true })).toBeVisible();
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
    await expect(page.getByPlaceholder('internal-app').first()).toBeVisible();
    await expect(page.getByRole('spinbutton')).toBeVisible(); // Port field
  });

  test('should create service successfully', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    // Use placeholder selectors - 'internal-app' is used for both name and host
    const nameInput = page.getByPlaceholder('internal-app').first();
    const hostInput = page.getByPlaceholder('internal-app').nth(1);
    const portInput = page.getByRole('spinbutton');

    await nameInput.fill('new-service');
    await hostInput.fill('192.168.1.100');
    await portInput.fill('3000');

    await page.getByRole('button', { name: /create service/i }).click();

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

  test('should create internal SSH server service with IP 192.168.31.76', async ({ page }) => {
    // Override POST mock to capture and verify SSH service creation
    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        // Verify the request body contains expected SSH service data
        expect(body.name).toBe('internal-ssh-server');
        expect(body.host).toBe('192.168.31.76');
        expect(body.port).toBe(22);
        expect(body.protocol).toBe('tcp');

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'ssh-service-id',
            ziti_id: 'svc-ssh-001',
            name: 'internal-ssh-server',
            description: 'Internal SSH Server',
            protocol: 'tcp',
            host: '192.168.31.76',
            port: 22,
            enabled: true,
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        // Handle GET requests with existing services plus new SSH service
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
      }
    });

    await page.goto('/ziti-network');

    // Navigate to services tab
    await page.getByRole('tab', { name: /services/i }).click();

    // Click Add Service button
    await page.getByRole('button', { name: /add service/i }).click();

    // Wait for create service modal to appear
    await expect(page.locator('text=Create Ziti Service')).toBeVisible();

    // Fill in the SSH service details using placeholder selectors
    const nameInput = page.getByPlaceholder('internal-app').first();
    const descInput = page.getByPlaceholder('Optional description');
    const hostInput = page.getByPlaceholder('internal-app').nth(1);
    const portInput = page.getByRole('spinbutton');

    await nameInput.fill('internal-ssh-server');
    await descInput.fill('Internal SSH Server');
    await hostInput.fill('192.168.31.76');
    await portInput.fill('22');

    // Protocol is already set to TCP by default

    // Submit the form
    await page.getByRole('button', { name: /create service/i }).click();

    // Verify success message
    await expect(page.locator('text=Service created').first()).toBeVisible();
  });

  test('should validate SSH service port 22 is valid', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    await page.getByRole('button', { name: /add service/i }).click();

    await expect(page.locator('text=Create Ziti Service')).toBeVisible();

    // Use placeholder selectors
    const nameInput = page.getByPlaceholder('internal-app').first();
    const hostInput = page.getByPlaceholder('internal-app').nth(1);
    const portInput = page.getByRole('spinbutton');

    // Fill with SSH standard port
    await nameInput.fill('ssh-test-service');
    await hostInput.fill('192.168.31.76');
    await portInput.fill('22');

    // Verify port field accepts value 22
    await expect(portInput).toHaveValue('22');
  });

  test('should display SSH service in services list after creation', async ({ page }) => {
    // Mock services list including the SSH server
    await page.route('**/api/v1/access/ziti/services', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            services: [
              { id: '1', ziti_id: 'svc-001', name: 'web-service', description: 'Web frontend', protocol: 'tcp', host: '10.0.0.1', port: 443, enabled: true, created_at: '2024-01-01T00:00:00Z' },
              { id: '2', ziti_id: 'svc-002', name: 'api-service', description: 'Backend API', protocol: 'tcp', host: '10.0.0.2', port: 8080, enabled: true, created_at: '2024-01-05T00:00:00Z' },
              { id: '3', ziti_id: 'svc-ssh-001', name: 'internal-ssh-server', description: 'Internal SSH Server', protocol: 'tcp', host: '192.168.31.76', port: 22, enabled: true, created_at: '2024-01-15T00:00:00Z' },
            ],
          }),
        });
      }
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /services/i }).click();

    // Verify SSH service is displayed
    await expect(page.locator('text=internal-ssh-server')).toBeVisible();
    await expect(page.locator('text=192.168.31.76')).toBeVisible();
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
    await expect(page.getByPlaceholder('john-laptop')).toBeVisible();
  });

  test('should show enrollment status', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /identities/i }).click();

    // Check that at least one enrolled badge is visible
    await expect(page.getByRole('cell', { name: 'Enrolled' }).first()).toBeVisible();
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

    // Note: API uses /posture/checks (not /posture-checks)
    await page.route('**/api/v1/access/ziti/posture/checks*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'OS Check', check_type: 'OS', enabled: true, severity: 'high', created_at: '2024-01-01T00:00:00Z' },
          { id: '2', name: 'MFA Check', check_type: 'MFA', enabled: true, severity: 'critical', created_at: '2024-01-05T00:00:00Z' },
        ]),
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

    // Use first() for strict mode since both checks are visible
    await expect(page.getByRole('cell', { name: 'OS Check' }).or(page.getByRole('cell', { name: 'MFA Check' })).first()).toBeVisible();
  });

  test('should show certificates section', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /security/i }).click();

    // Use first() for strict mode
    await expect(page.getByRole('cell', { name: 'Root CA', exact: true }).or(page.getByRole('button', { name: 'Certificates' })).first()).toBeVisible();
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

    // Wait for content to load - look for BrowZer heading within the tab content
    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
  });

  test('should show BrowZer status', async ({ page }) => {
    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
  });

  test('should display external SSH connection for 192.168.31.76', async ({ page }) => {
    // Mock Guacamole connections with SSH to internal server
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connections: [
            {
              id: 'ssh-conn-1',
              route_id: 'route-ssh-internal',
              guacamole_connection_id: 'guac-ssh-001',
              protocol: 'ssh',
              hostname: '192.168.31.76',
              port: 22,
              parameters: { username: 'admin' },
              created_at: '2024-01-15T00:00:00Z',
              updated_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify SSH connection to internal server is displayed
    await expect(page.locator('text=192.168.31.76:22')).toBeVisible();
    await expect(page.locator('td:has-text("ssh")').first()).toBeVisible();
  });

  test('should display Guacamole SSH access URL for 192.168.31.76', async ({ page }) => {
    // Mock BrowZer status - base URL only
    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.localtest.me/',
          oidc_issuer: 'https://auth.localtest.me',
          oidc_client_id: 'browzer-client',
          external_jwt_signer_id: 'jwt-signer-001',
        }),
      });
    });

    // Mock Guacamole connections with SSH to internal server
    // Guacamole uses path: /guacamole/#/client/{encoded-connection-id}
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connections: [
            {
              id: 'ssh-conn-1',
              route_id: 'route-ssh-internal',
              guacamole_connection_id: 'c/internal-ssh-server',
              protocol: 'ssh',
              hostname: '192.168.31.76',
              port: 22,
              // Full Guacamole URL with path
              connect_url: 'https://browzer.localtest.me/guacamole/#/client/c/internal-ssh-server',
              parameters: { username: 'admin' },
              created_at: '2024-01-15T00:00:00Z',
              updated_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    // Mock services list with SSH service
    await page.route('**/api/v1/access/ziti/services*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          services: [
            {
              id: 'ssh-svc-1',
              ziti_id: 'svc-ssh-001',
              name: 'internal-ssh-server',
              description: 'Internal SSH Server',
              protocol: 'tcp',
              host: '192.168.31.76',
              port: 22,
              enabled: true,
              created_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    // Mock connect endpoint - returns Guacamole URL with /guacamole path
    await page.route('**/api/v1/access/guacamole/connections/*/connect', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connect_url: 'https://browzer.localtest.me/guacamole/#/client/c/internal-ssh-server',
        }),
      });
    });

    await page.goto('/ziti-network');

    // Navigate to Remote Access tab
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify BrowZer is enabled
    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
    await expect(page.locator('text=Enabled').first()).toBeVisible();

    // Verify SSH connection details
    await expect(page.locator('text=192.168.31.76').first()).toBeVisible();
    await expect(page.getByText(':22').first()).toBeVisible();

    // Verify Connect button exists for Guacamole access
    await expect(page.getByRole('button', { name: /connect/i })).toBeVisible();
  });

  test('should have Connect button for SSH external access', async ({ page }) => {
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connections: [
            {
              id: 'ssh-conn-1',
              route_id: 'route-ssh-internal',
              guacamole_connection_id: 'guac-ssh-001',
              protocol: 'ssh',
              hostname: '192.168.31.76',
              port: 22,
              parameters: {},
              created_at: '2024-01-15T00:00:00Z',
              updated_at: '2024-01-15T00:00:00Z',
            },
          ],
        }),
      });
    });

    // Mock connect endpoint
    await page.route('**/api/v1/access/guacamole/connections/*/connect', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          connect_url: 'https://guacamole.example.com/#/client/c/guac-ssh-001',
        }),
      });
    });

    await page.goto('/ziti-network');

    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify Connect button is available
    await expect(page.getByRole('button', { name: /connect/i })).toBeVisible();
  });
});
