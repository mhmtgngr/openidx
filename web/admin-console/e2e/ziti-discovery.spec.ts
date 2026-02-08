import { test, expect } from '@playwright/test';

const mockDiscoveryResult = {
  discovered_services: [
    {
      ziti_id: 'ziti-svc-001',
      name: 'backend-api',
      protocol: 'tcp',
      host: '10.0.0.5',
      port: 8080,
      managed_by_openidx: false,
      can_import: true,
      role_attributes: ['api', 'backend'],
    },
    {
      ziti_id: 'ziti-svc-002',
      name: 'database-primary',
      protocol: 'tcp',
      host: '10.0.0.10',
      port: 5432,
      managed_by_openidx: false,
      can_import: true,
      role_attributes: ['database'],
    },
    {
      ziti_id: 'ziti-svc-003',
      name: 'demo-app-zt',
      protocol: 'tcp',
      host: 'demo-app',
      port: 8090,
      managed_by_openidx: true,
      can_import: false,
      role_attributes: ['openidx-managed'],
    },
  ],
  already_managed: 1,
  available_for_import: 2,
  discovered_at: new Date().toISOString(),
};

test.describe('Ziti Service Discovery', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/discover', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockDiscoveryResult),
        });
      }
    });
  });

  test('should display page title and summary cards', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await expect(page.getByText('Ziti Service Discovery')).toBeVisible();
    await expect(page.getByText('Total Services')).toBeVisible();
    await expect(page.getByText('Already Managed')).toBeVisible();
    await expect(page.getByText('Available to Import')).toBeVisible();

    // Verify counts
    await expect(page.getByText('3').first()).toBeVisible(); // total
  });

  test('should display discovered services in table', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await expect(page.getByText('backend-api')).toBeVisible();
    await expect(page.getByText('database-primary')).toBeVisible();
    await expect(page.getByText('demo-app-zt')).toBeVisible();

    // Check host:port
    await expect(page.getByText('10.0.0.5:8080')).toBeVisible();
    await expect(page.getByText('10.0.0.10:5432')).toBeVisible();
  });

  test('should show Managed and Available badges', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await expect(page.getByText('Managed')).toBeVisible();
    const availableBadges = page.getByText('Available');
    await expect(availableBadges.first()).toBeVisible();
  });

  test('should show Import buttons only for importable services', async ({ page }) => {
    await page.goto('/ziti-discovery');

    // backend-api and database-primary should have Import buttons
    const importButtons = page.getByRole('button', { name: /^Import$/ });
    await expect(importButtons).toHaveCount(2);
  });

  test('should filter services by search', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await page.getByPlaceholder('Search services...').fill('backend');

    // Only backend-api should be visible
    await expect(page.getByText('backend-api')).toBeVisible();
    await expect(page.getByText('database-primary')).not.toBeVisible();
    await expect(page.getByText('demo-app-zt')).not.toBeVisible();
  });

  test('should open single import modal when clicking Import', async ({ page }) => {
    await page.goto('/ziti-discovery');

    // Click Import on first available service
    await page.getByRole('button', { name: /^Import$/ }).first().click();

    await expect(page.getByText('Import Ziti Service')).toBeVisible();
    await expect(page.getByPlaceholder('Enter route name')).toBeVisible();
    await expect(page.getByPlaceholder('/my-service')).toBeVisible();
    await expect(page.getByPlaceholder('Enter description')).toBeVisible();
  });

  test('should pre-fill route name from service name', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await page.getByRole('button', { name: /^Import$/ }).first().click();

    await expect(page.getByText('Import Ziti Service')).toBeVisible();
    const routeNameInput = page.getByPlaceholder('Enter route name');
    await expect(routeNameInput).toHaveValue('backend-api');
  });

  test('should submit single import request', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    await page.route('**/api/v1/access/ziti/import', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            route_id: 'new-route-123',
            message: 'Service imported successfully',
          }),
        });
      }
    });

    await page.goto('/ziti-discovery');

    await page.getByRole('button', { name: /^Import$/ }).first().click();
    await expect(page.getByText('Import Ziti Service')).toBeVisible();

    // Modify description
    await page.getByPlaceholder('Enter description').fill('Backend API service');

    // Submit
    await page.locator('button:has-text("Import")').last().click();

    await expect(page.getByText('Service Imported').first()).toBeVisible({ timeout: 5000 });

    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).ziti_id).toBe('ziti-svc-001');
    expect((capturedRequest as Record<string, unknown>).route_name).toBe('backend-api');
    expect((capturedRequest as Record<string, unknown>).description).toBe('Backend API service');
  });

  test('should select services for bulk import', async ({ page }) => {
    await page.goto('/ziti-discovery');

    // Select first importable service
    const checkboxes = page.locator('tbody tr td:first-child button[role="checkbox"]');
    await checkboxes.first().click();

    // Import Selected button should show count
    await expect(page.getByRole('button', { name: /Import Selected \(1\)/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /Import Selected \(1\)/ })).toBeEnabled();
  });

  test('should select all importable services', async ({ page }) => {
    await page.goto('/ziti-discovery');

    // Click select-all checkbox in header
    const headerCheckbox = page.locator('thead button[role="checkbox"]');
    await headerCheckbox.click();

    await expect(page.getByRole('button', { name: /Import Selected \(2\)/ })).toBeVisible();
  });

  test('should open bulk import confirmation dialog', async ({ page }) => {
    await page.goto('/ziti-discovery');

    // Select all
    const headerCheckbox = page.locator('thead button[role="checkbox"]');
    await headerCheckbox.click();

    // Click Import Selected
    await page.getByRole('button', { name: /Import Selected/ }).click();

    await expect(page.getByText('Confirm Bulk Import')).toBeVisible();
    await expect(page.getByRole('button', { name: /Import 2 Services/ })).toBeVisible();
  });

  test('should submit bulk import request', async ({ page }) => {
    let capturedRequest: Record<string, unknown> | null = null;

    await page.route('**/api/v1/access/ziti/import/bulk', async (route) => {
      if (route.request().method() === 'POST') {
        capturedRequest = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            total_imported: 2,
            total_failed: 0,
            results: [
              { ziti_id: 'ziti-svc-001', success: true },
              { ziti_id: 'ziti-svc-002', success: true },
            ],
          }),
        });
      }
    });

    await page.goto('/ziti-discovery');

    // Select all and import
    const headerCheckbox = page.locator('thead button[role="checkbox"]');
    await headerCheckbox.click();
    await page.getByRole('button', { name: /Import Selected/ }).click();

    // Confirm
    await expect(page.getByText('Confirm Bulk Import')).toBeVisible();
    await page.getByRole('button', { name: /Import 2 Services/ }).click();

    await expect(page.getByText('Bulk Import Complete').first()).toBeVisible({ timeout: 5000 });

    expect(capturedRequest).toBeTruthy();
    expect((capturedRequest as Record<string, unknown>).ziti_ids).toEqual(['ziti-svc-001', 'ziti-svc-002']);
  });

  test('should show error toast on import failure', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/import', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Ziti controller unreachable' }),
        });
      }
    });

    await page.goto('/ziti-discovery');

    await page.getByRole('button', { name: /^Import$/ }).first().click();
    await expect(page.getByText('Import Ziti Service')).toBeVisible();
    await page.locator('button:has-text("Import")').last().click();

    await expect(page.getByText('Import Failed').first()).toBeVisible({ timeout: 5000 });
  });

  test('should have refresh button', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await expect(page.getByRole('button', { name: /Refresh/ })).toBeVisible();
  });

  test('should cancel single import modal', async ({ page }) => {
    await page.goto('/ziti-discovery');

    await page.getByRole('button', { name: /^Import$/ }).first().click();
    await expect(page.getByText('Import Ziti Service')).toBeVisible();

    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByText('Import Ziti Service')).not.toBeVisible();
  });

  test('should disable Import Selected button when nothing selected', async ({ page }) => {
    await page.goto('/ziti-discovery');

    const importSelectedBtn = page.getByRole('button', { name: /Import Selected \(0\)/ });
    await expect(importSelectedBtn).toBeDisabled();
  });

  test('should show empty state when no services found', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/discover', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          discovered_services: [],
          already_managed: 0,
          available_for_import: 0,
          discovered_at: new Date().toISOString(),
        }),
      });
    });

    await page.goto('/ziti-discovery');

    await expect(page.getByText('No services found')).toBeVisible();
  });
});
