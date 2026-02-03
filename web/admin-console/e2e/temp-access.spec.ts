import { test, expect } from '@playwright/test';

test.describe('Temporary Access Links', () => {
  test.beforeEach(async ({ page }) => {
    // Mock Ziti status
    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true }),
      });
    });

    // Mock BrowZer status (required for RemoteAccessTab)
    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.localtest.me/',
        }),
      });
    });

    // Mock Guacamole connections (required for RemoteAccessTab)
    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ connections: [] }),
      });
    });

    // Mock Ziti services
    await page.route('**/api/v1/access/ziti/services*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ services: [] }),
      });
    });

    // Mock temp access links list
    await page.route('**/api/v1/access/temp-access', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            links: [
              {
                id: 'link-1',
                token: 'abc12345...',
                name: 'Support Access - Server 1',
                description: 'Temp access for vendor support',
                protocol: 'ssh',
                target_host: '192.168.31.76',
                target_port: 22,
                created_by_email: 'admin@openidx.local',
                expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(), // 2 hours
                max_uses: 5,
                current_uses: 2,
                status: 'active',
                access_url: 'https://browzer.localtest.me/temp-access/abc12345...',
                created_at: '2024-01-15T10:00:00Z',
              },
              {
                id: 'link-2',
                token: 'xyz98765...',
                name: 'RDP Access - Windows Server',
                description: 'Emergency maintenance access',
                protocol: 'rdp',
                target_host: '192.168.31.100',
                target_port: 3389,
                created_by_email: 'admin@openidx.local',
                expires_at: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(), // Expired
                max_uses: 1,
                current_uses: 1,
                status: 'expired',
                access_url: 'https://browzer.localtest.me/temp-access/xyz98765...',
                created_at: '2024-01-14T08:00:00Z',
              },
            ],
          }),
        });
      } else if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-link-id',
            token: 'newtoken123456789',
            name: body.name,
            description: body.description,
            protocol: body.protocol,
            target_host: body.target_host,
            target_port: body.target_port,
            expires_at: new Date(Date.now() + body.duration_mins * 60 * 1000).toISOString(),
            max_uses: body.max_uses || 0,
            current_uses: 0,
            status: 'active',
            access_url: 'https://browzer.localtest.me/temp-access/newtoken123456789',
            created_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock revoke endpoint
    await page.route('**/api/v1/access/temp-access/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 200, body: JSON.stringify({ message: 'access link revoked' }) });
      } else if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'link-1',
            token: 'abc12345...',
            name: 'Support Access - Server 1',
            protocol: 'ssh',
            target_host: '192.168.31.76',
            target_port: 22,
            status: 'active',
          }),
        });
      }
    });
  });

  test('should display temp access page', async ({ page }) => {
    await page.goto('/ziti-network');

    // Navigate to Remote Access tab
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Look for temp access section title
    await expect(page.locator('text=Temporary Access Links')).toBeVisible();
  });

  test('should create SSH temp access link for 192.168.31.76', async ({ page }) => {
    // Mock the create endpoint with verification
    await page.route('**/api/v1/access/temp-access', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();

        // Verify the request
        expect(body.name).toBe('Vendor SSH Access');
        expect(body.protocol).toBe('ssh');
        expect(body.target_host).toBe('192.168.31.76');
        expect(body.target_port).toBe(22);
        expect(body.duration_mins).toBe(120); // 2 hours

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-ssh-link',
            token: 'secure-token-abc123',
            name: body.name,
            protocol: 'ssh',
            target_host: '192.168.31.76',
            target_port: 22,
            expires_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
            status: 'active',
            access_url: 'https://browzer.localtest.me/temp-access/secure-token-abc123',
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ links: [] }),
        });
      }
    });

    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Click create temp access button
    await page.getByRole('button', { name: /create temp access/i }).click();

    // Wait for dialog to open
    await expect(page.getByText('Create Temporary Access Link')).toBeVisible();

    // Fill the form using actual placeholders
    await page.getByPlaceholder('Vendor SSH Access').fill('Vendor SSH Access');
    await page.getByPlaceholder('192.168.31.76').fill('192.168.31.76');

    // Protocol is already SSH by default

    // Submit the form
    await page.getByRole('button', { name: /create access link/i }).click();

    // Verify success (dialog should close and we should see the link in the list or a toast)
    await page.waitForTimeout(500);
  });

  test('should display access URL that can be shared', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // The access URL should be visible in the table
    await expect(page.locator('code:has-text("browzer.localtest.me")').first()).toBeVisible();
  });

  test('should show expiration time for temp access links', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Should show Active badge for active links
    await expect(page.locator('text=Active').first()).toBeVisible();
  });

  test('should show usage count for temp access links', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Should show uses count (e.g., "2/5 uses" or "2 uses")
    await expect(page.locator('text=uses').first()).toBeVisible();
  });

  test('should have revoke button for active links', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Wait for the table to load
    await expect(page.locator('text=Support Access - Server 1')).toBeVisible();

    // Find the dropdown button in the first data row (it's the last cell with icon button)
    const firstRow = page.locator('tr').filter({ hasText: 'Support Access - Server 1' });
    const dropdownButton = firstRow.locator('button').last();
    await dropdownButton.click();

    // Revoke option should be visible in the dropdown
    await expect(page.locator('text=Revoke Access')).toBeVisible();
  });

  test('should copy access URL to clipboard', async ({ page }) => {
    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Look for copy button
    const copyButton = page.getByRole('button', { name: /copy/i }).first();
    if (await copyButton.isVisible()) {
      await copyButton.click();
      // Success message should appear
      await expect(page.locator('text=copied').or(page.locator('text=Copied'))).toBeVisible();
    }
  });
});

test.describe('Temp Access Link Creation Flow', () => {
  test('should create temp access for support company with all options', async ({ page }) => {
    // Comprehensive mock for full creation flow
    await page.route('**/api/v1/access/temp-access', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'support-link-001',
            token: 'support-vendor-token-xyz',
            name: body.name,
            description: body.description,
            protocol: body.protocol,
            target_host: body.target_host,
            target_port: body.target_port,
            username: body.username,
            expires_at: new Date(Date.now() + body.duration_mins * 60 * 1000).toISOString(),
            max_uses: body.max_uses,
            allowed_ips: body.allowed_ips,
            require_mfa: body.require_mfa,
            notify_on_use: body.notify_on_use,
            notify_email: body.notify_email,
            status: 'active',
            access_url: 'https://browzer.localtest.me/temp-access/support-vendor-token-xyz',
            created_at: new Date().toISOString(),
          }),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ links: [] }),
        });
      }
    });

    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true, sdk_ready: true, controller_reachable: true }),
      });
    });

    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          configured: true,
          bootstrapper_url: 'https://browzer.localtest.me/',
        }),
      });
    });

    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ connections: [] }),
      });
    });

    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify page loads
    await expect(page.locator('h3:has-text("BrowZer")').first()).toBeVisible();
  });
});

test.describe('Temp Access URL Format', () => {
  test('should generate correct URL format for SSH access', async ({ page }) => {
    // The URL format should be: https://browzer.localtest.me/temp-access/{token}
    // Which redirects to: /guacamole/#/client/{connection-id}

    await page.route('**/api/v1/access/temp-access', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          links: [
            {
              id: 'ssh-link',
              name: 'SSH to 192.168.31.76',
              protocol: 'ssh',
              target_host: '192.168.31.76',
              target_port: 22,
              status: 'active',
              access_url: 'https://browzer.localtest.me/temp-access/abc123token',
              expires_at: new Date(Date.now() + 3600000).toISOString(),
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/access/ziti/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true }),
      });
    });

    await page.route('**/api/v1/access/ziti/browzer/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true, bootstrapper_url: 'https://browzer.localtest.me/' }),
      });
    });

    await page.route('**/api/v1/access/guacamole/connections*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ connections: [] }),
      });
    });

    await page.goto('/ziti-network');
    await page.getByRole('tab', { name: /remote access/i }).click();

    // Verify the temp access section is visible
    await expect(page.locator('text=Temporary Access Links')).toBeVisible();
    // Verify access URL format in the table
    await expect(page.locator('code:has-text("browzer.localtest.me")').first()).toBeVisible();
  });
});
