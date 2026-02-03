import { test, expect } from '@playwright/test';

test.describe('OAuth Client Registration', () => {
  test.beforeEach(async ({ page }) => {
    // Mock applications API
    await page.route('**/api/v1/applications*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '2' },
          body: JSON.stringify([
            { id: '1', client_id: 'admin-console', name: 'Admin Console', description: 'OpenIDX Admin Dashboard', type: 'web', protocol: 'oidc', base_url: 'http://localhost:3000', redirect_uris: ['http://localhost:3000/login'], enabled: true, pkce_required: true, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' },
            { id: '2', client_id: 'mobile-app', name: 'Mobile App', description: 'iOS/Android App', type: 'native', protocol: 'oidc', base_url: '', redirect_uris: ['myapp://callback'], enabled: true, pkce_required: true, created_at: '2024-01-15T00:00:00Z', updated_at: '2024-01-15T00:00:00Z' },
          ]),
        });
      }
    });

    // Mock OAuth clients API for creation
    await page.route('**/api/v1/oauth/clients', async (route) => {
      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-client-id',
            client_id: 'new-app-' + Date.now(),
            client_secret: 'secret_' + Math.random().toString(36).substring(7),
            ...body,
            enabled: true,
            created_at: new Date().toISOString(),
          }),
        });
      }
    });

    // Mock regenerate secret
    await page.route('**/api/v1/oauth/clients/*/regenerate-secret', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          client_secret: 'new_secret_' + Math.random().toString(36).substring(7),
        }),
      });
    });
  });

  test('should display applications page', async ({ page }) => {
    await page.goto('/applications');

    await expect(page.locator('h1:has-text("Applications")')).toBeVisible();
    await expect(page.locator('text=Manage registered applications')).toBeVisible();
  });

  test('should display registered applications', async ({ page }) => {
    await page.goto('/applications');

    await expect(page.locator('text=Admin Console')).toBeVisible();
    await expect(page.locator('text=Mobile App')).toBeVisible();
  });

  test('should display application types with badges', async ({ page }) => {
    await page.goto('/applications');

    // Check for type badges
    await expect(page.locator('text=web').first()).toBeVisible();
    await expect(page.locator('text=native')).toBeVisible();
  });

  test('should have Register Application button', async ({ page }) => {
    await page.goto('/applications');

    await expect(page.getByRole('button', { name: /register application/i })).toBeVisible();
  });

  test('should open registration modal', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    await expect(page.locator('text=Register OAuth/OIDC Application')).toBeVisible();
  });

  test('should display all registration form fields', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Check all form fields
    await expect(page.getByLabel(/application name/i)).toBeVisible();
    await expect(page.getByLabel(/description/i)).toBeVisible();
    await expect(page.getByLabel(/redirect uris/i)).toBeVisible();
    await expect(page.getByLabel(/scopes/i)).toBeVisible();
    await expect(page.getByLabel(/require pkce/i)).toBeVisible();
  });

  test('should have application type selector', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Check for type selector
    await expect(page.locator('text=Application Type').first()).toBeVisible();

    // Click on the select trigger
    const selectTrigger = page.locator('[role="combobox"]').first();
    await selectTrigger.click();

    // Check options
    await expect(page.locator('[role="option"]:has-text("Web Application")')).toBeVisible();
    await expect(page.locator('[role="option"]:has-text("Native/Mobile App")')).toBeVisible();
    await expect(page.locator('[role="option"]:has-text("Service/Machine-to-Machine")')).toBeVisible();
  });

  test('should validate required application name', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Fill only redirect URIs, leave name empty
    await page.getByLabel(/redirect uris/i).fill('http://localhost:3000/callback');

    await page.getByRole('button', { name: /register application$/i }).click();

    // Modal should still be visible (form not submitted)
    await expect(page.locator('text=Register OAuth/OIDC Application')).toBeVisible();
  });

  test('should validate required redirect URIs', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Fill name but leave redirect URIs empty
    await page.getByLabel(/application name/i).fill('Test App');

    await page.getByRole('button', { name: /register application$/i }).click();

    // Modal should still be visible
    await expect(page.locator('text=Register OAuth/OIDC Application')).toBeVisible();
  });

  test('should register application successfully', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Fill the form
    await page.getByLabel(/application name/i).fill('Test Application');
    await page.getByLabel(/description/i).fill('A test OAuth application');
    await page.getByLabel(/redirect uris/i).fill('http://localhost:8080/callback');
    await page.getByLabel(/scopes/i).fill('openid,profile,email');

    await page.getByRole('button', { name: /register application$/i }).click();

    // Modal should close on success
    await expect(page.locator('text=Register OAuth/OIDC Application')).not.toBeVisible({ timeout: 5000 });

    // Success toast should appear
    await expect(page.locator('text=OAuth client created').first()).toBeVisible();
  });

  test('should show information about client credentials after registration', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Check for credential info text
    await expect(page.locator('text=Client ID').first()).toBeVisible();
    await expect(page.locator('text=Client Secret').first()).toBeVisible();
    await expect(page.locator("text=Store the Client Secret securely")).toBeVisible();
  });

  test('should default PKCE checkbox to checked', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    const pkceCheckbox = page.getByLabel(/require pkce/i);
    await expect(pkceCheckbox).toBeChecked();
  });

  test('should toggle PKCE checkbox', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    const pkceCheckbox = page.getByLabel(/require pkce/i);
    await expect(pkceCheckbox).toBeChecked();

    await pkceCheckbox.uncheck();
    await expect(pkceCheckbox).not.toBeChecked();

    await pkceCheckbox.check();
    await expect(pkceCheckbox).toBeChecked();
  });

  test('should close registration modal on cancel', async ({ page }) => {
    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();
    await expect(page.locator('text=Register OAuth/OIDC Application')).toBeVisible();

    await page.getByRole('button', { name: /cancel/i }).click();

    await expect(page.locator('text=Register OAuth/OIDC Application')).not.toBeVisible();
  });

  test('should show error on registration failure', async ({ page }) => {
    await page.route('**/api/v1/oauth/clients', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Client name already exists' }),
        });
      }
    });

    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    await page.getByLabel(/application name/i).fill('Existing App');
    await page.getByLabel(/redirect uris/i).fill('http://localhost/callback');

    await page.getByRole('button', { name: /register application$/i }).click();

    // Error toast should appear
    await expect(page.locator('text=Failed to create OAuth client').first()).toBeVisible();
  });
});

test.describe('Application Management Actions', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/applications*', async (route) => {
      const url = route.request().url();
      if (route.request().method() === 'GET' && !url.includes('/sso-settings')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '1' },
          body: JSON.stringify([
            { id: '1', client_id: 'test-client', name: 'Test App', description: 'Test', type: 'web', protocol: 'oidc', base_url: 'http://localhost', redirect_uris: ['http://localhost/callback'], enabled: true, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' },
          ]),
        });
      }
    });

    await page.route('**/api/v1/oauth/clients/*/regenerate-secret', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ client_secret: 'new_secret_abc123xyz' }),
      });
    });
  });

  test('should open action menu', async ({ page }) => {
    await page.goto('/applications');

    await expect(page.locator('text=Test App')).toBeVisible();

    // Click the action menu button
    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    // Check dropdown items
    await expect(page.locator('text=Edit Application')).toBeVisible();
    await expect(page.locator('text=Copy Client ID')).toBeVisible();
    await expect(page.locator('text=Regenerate Secret')).toBeVisible();
    await expect(page.locator('text=SSO Settings')).toBeVisible();
    await expect(page.locator('text=Delete Application')).toBeVisible();
  });

  test('should copy client ID to clipboard', async ({ page, context }) => {
    // Grant clipboard permissions
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);

    await page.goto('/applications');

    await expect(page.locator('text=Test App')).toBeVisible();

    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    await page.locator('text=Copy Client ID').click();

    // Success toast should appear
    await expect(page.locator('text=Client ID copied').first()).toBeVisible();
  });

  test('should open regenerate secret modal', async ({ page }) => {
    await page.goto('/applications');

    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    await page.locator('text=Regenerate Secret').click();

    await expect(page.locator('text=Regenerate Client Secret')).toBeVisible();
    await expect(page.locator('text=Are you sure you want to regenerate')).toBeVisible();
  });

  test('should regenerate secret and show new secret', async ({ page }) => {
    await page.goto('/applications');

    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    await page.locator('text=Regenerate Secret').click();

    // Click regenerate button in modal
    await page.getByRole('button', { name: /regenerate secret$/i }).click();

    // Should show new secret
    await expect(page.locator('text=Save this secret now')).toBeVisible();
    await expect(page.locator('text=New Client Secret')).toBeVisible();
    await expect(page.locator('code:has-text("new_secret")')).toBeVisible();
  });

  test('should open edit application modal', async ({ page }) => {
    await page.goto('/applications');

    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    await page.locator('text=Edit Application').click();

    await expect(page.locator('text=Edit Application').first()).toBeVisible();
    await expect(page.getByLabel(/application name/i)).toHaveValue('Test App');
  });

  test('should open SSO settings modal', async ({ page }) => {
    await page.route('**/api/v1/applications/1/sso-settings', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          enabled: true,
          use_refresh_tokens: true,
          access_token_lifetime: 3600,
          refresh_token_lifetime: 86400,
          require_consent: false,
        }),
      });
    });

    await page.goto('/applications');

    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    await page.locator('text=SSO Settings').click();

    await expect(page.locator('text=SSO Settings - Test App')).toBeVisible();
    await expect(page.getByLabel(/sso enabled/i)).toBeVisible();
    await expect(page.getByLabel(/use refresh tokens/i)).toBeVisible();
    await expect(page.getByLabel(/access token lifetime/i)).toBeVisible();
  });

  test('should show delete confirmation', async ({ page }) => {
    await page.goto('/applications');

    const actionButton = page.locator('tr').filter({ hasText: 'Test App' }).getByRole('button').last();
    await actionButton.click();

    await page.locator('text=Delete Application').click();

    await expect(page.getByRole('heading', { name: 'Are you sure?' })).toBeVisible();
    await expect(page.locator('text=delete application "Test App"')).toBeVisible();
  });
});

test.describe('Application Search and Filter', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/applications*', async (route) => {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';

      const allApps = [
        { id: '1', client_id: 'web-app', name: 'Web Application', description: 'Frontend', type: 'web', protocol: 'oidc', enabled: true, created_at: '2024-01-01T00:00:00Z' },
        { id: '2', client_id: 'mobile-app', name: 'Mobile App', description: 'iOS/Android', type: 'native', protocol: 'oidc', enabled: true, created_at: '2024-01-15T00:00:00Z' },
        { id: '3', client_id: 'api-service', name: 'API Service', description: 'Backend', type: 'service', protocol: 'oidc', enabled: false, created_at: '2024-02-01T00:00:00Z' },
      ];

      const filtered = search
        ? allApps.filter(a => a.name.toLowerCase().includes(search.toLowerCase()))
        : allApps;

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': String(filtered.length) },
        body: JSON.stringify(filtered),
      });
    });
  });

  test('should have search input', async ({ page }) => {
    await page.goto('/applications');

    await expect(page.getByPlaceholder(/search applications/i)).toBeVisible();
  });

  test('should filter applications by search', async ({ page }) => {
    await page.goto('/applications');

    await expect(page.locator('text=Web Application')).toBeVisible();
    await expect(page.locator('text=Mobile App')).toBeVisible();
    await expect(page.locator('text=API Service')).toBeVisible();

    await page.getByPlaceholder(/search applications/i).fill('Mobile');

    await expect(page.locator('text=Mobile App')).toBeVisible();
    await expect(page.locator('text=Web Application')).not.toBeVisible();
    await expect(page.locator('text=API Service')).not.toBeVisible();
  });

  test('should show no applications message when search has no results', async ({ page }) => {
    await page.route('**/api/v1/applications*', async (route) => {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';

      if (search === 'nonexistent') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '0' },
          body: JSON.stringify([]),
        });
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '1' },
          body: JSON.stringify([{ id: '1', name: 'Test', client_id: 'test', type: 'web', enabled: true }]),
        });
      }
    });

    await page.goto('/applications');

    await page.getByPlaceholder(/search applications/i).fill('nonexistent');

    await expect(page.locator('text=No applications found')).toBeVisible();
  });
});

test.describe('OAuth Login Flow Conditions', () => {
  test('should handle disabled application', async ({ page }) => {
    await page.route('**/api/v1/applications*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '1' },
        body: JSON.stringify([
          { id: '1', client_id: 'disabled-app', name: 'Disabled App', type: 'web', protocol: 'oidc', enabled: false, created_at: '2024-01-01T00:00:00Z' },
        ]),
      });
    });

    await page.goto('/applications');

    // Check that disabled status is shown
    await expect(page.locator('text=Disabled')).toBeVisible();
  });

  test('should display different application types correctly', async ({ page }) => {
    await page.route('**/api/v1/applications*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': '3' },
        body: JSON.stringify([
          { id: '1', client_id: 'web', name: 'Web App', type: 'web', protocol: 'oidc', enabled: true, created_at: '2024-01-01T00:00:00Z' },
          { id: '2', client_id: 'native', name: 'Native App', type: 'native', protocol: 'oidc', enabled: true, created_at: '2024-01-01T00:00:00Z' },
          { id: '3', client_id: 'service', name: 'Service App', type: 'service', protocol: 'oidc', enabled: true, created_at: '2024-01-01T00:00:00Z' },
        ]),
      });
    });

    await page.goto('/applications');

    // Check all types are displayed
    await expect(page.locator('text=web').first()).toBeVisible();
    await expect(page.locator('text=native')).toBeVisible();
    await expect(page.locator('text=service')).toBeVisible();
  });

  test('should show type description when selecting application type', async ({ page }) => {
    await page.route('**/api/v1/applications*', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', headers: { 'x-total-count': '0' }, body: '[]' });
    });

    await page.goto('/applications');

    await page.getByRole('button', { name: /register application/i }).click();

    // Select web type
    const selectTrigger = page.locator('[role="combobox"]').first();
    await selectTrigger.click();
    await page.locator('[role="option"]:has-text("Web Application")').click();

    await expect(page.locator('text=Server-side web applications')).toBeVisible();

    // Select native type
    await selectTrigger.click();
    await page.locator('[role="option"]:has-text("Native/Mobile App")').click();

    await expect(page.locator('text=Mobile or desktop applications')).toBeVisible();

    // Select service type
    await selectTrigger.click();
    await page.locator('[role="option"]:has-text("Service/Machine-to-Machine")').click();

    await expect(page.locator('text=Backend services using client credentials')).toBeVisible();
  });
});
