import { test, expect } from '@playwright/test';

test.describe('JIT Access — Duration Picker', () => {
  test.beforeEach(async ({ page }) => {
    // Mock access requests API
    await page.route('**/api/v1/governance/requests*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ requests: [] }),
        });
      } else if (route.request().method() === 'POST' && !route.request().url().includes('/cancel') && !route.request().url().includes('/approve') && !route.request().url().includes('/deny')) {
        const body = JSON.parse(route.request().postData() || '{}');
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-request-id',
            ...body,
            requester_id: 'user-1',
            status: 'pending',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.route('**/api/v1/governance/my-approvals', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ pending_approvals: [] }),
      });
    });

    await page.goto('/access-requests');
  });

  test('should show duration picker in create request dialog', async ({ page }) => {
    await page.getByRole('button', { name: /Request Access/i }).click();

    // Duration field should be visible
    await expect(page.locator('text=Access Duration')).toBeVisible();
    await expect(page.locator('text=Access will not expire automatically')).toBeVisible();
  });

  test('should show duration options when selecting duration', async ({ page }) => {
    await page.getByRole('button', { name: /Request Access/i }).click();

    // Click the duration dropdown
    const durationTrigger = page.locator('text=Permanent').first();
    await durationTrigger.click();

    // Duration options should be visible
    await expect(page.getByRole('option', { name: '4 hours' })).toBeVisible();
    await expect(page.getByRole('option', { name: '1 day' })).toBeVisible();
    await expect(page.getByRole('option', { name: '7 days' })).toBeVisible();
    await expect(page.getByRole('option', { name: '30 days' })).toBeVisible();
    await expect(page.getByRole('option', { name: '90 days' })).toBeVisible();
  });

  test('should show expiry message when duration is selected', async ({ page }) => {
    await page.getByRole('button', { name: /Request Access/i }).click();

    // Select a duration
    const durationTrigger = page.locator('text=Permanent').first();
    await durationTrigger.click();
    await page.getByRole('option', { name: '7 days' }).click();

    // Should show expiry message
    await expect(page.locator('text=Access will be automatically revoked')).toBeVisible();
  });

  test('should submit request with duration', async ({ page }) => {
    await page.getByRole('button', { name: /Request Access/i }).click();

    // Fill form
    const typeSelect = page.locator('text=Select type');
    await typeSelect.click();
    await page.getByRole('option', { name: 'Role' }).click();

    await page.getByPlaceholder('Enter resource name').fill('admin-role');
    await page.getByPlaceholder('Explain why you need access').fill('Temporary admin access for maintenance');

    // Select duration
    const durationTrigger = page.locator('text=Permanent').first();
    await durationTrigger.click();
    await page.getByRole('option', { name: '4 hours' }).click();

    // Capture the POST request
    const requestPromise = page.waitForRequest((req) =>
      req.url().includes('/api/v1/governance/requests') && req.method() === 'POST'
    );

    await page.getByRole('button', { name: /Submit Request/i }).click();
    const request = await requestPromise;
    const postedData = JSON.parse(request.postData() || '{}');

    expect(postedData.resource_type).toBe('role');
    expect(postedData.resource_name).toBe('admin-role');
    expect(postedData.duration).toBe('4h');
  });
});

test.describe('JIT Access — Expiry Badge', () => {
  test('should show expiry badge on requests with expires_at', async ({ page }) => {
    const futureDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    await page.route('**/api/v1/governance/requests*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          requests: [
            {
              id: 'req-1',
              requester_id: 'user-1',
              requester_name: 'John Smith',
              resource_name: 'Admin Role',
              resource_type: 'role',
              status: 'fulfilled',
              priority: 'normal',
              justification: 'Temp access',
              expires_at: futureDate,
              created_at: '2026-02-10T00:00:00Z',
              updated_at: '2026-02-10T00:00:00Z',
            },
            {
              id: 'req-2',
              requester_id: 'user-1',
              requester_name: 'John Smith',
              resource_name: 'Dev Group',
              resource_type: 'group',
              status: 'expired',
              priority: 'normal',
              justification: 'Past access',
              expires_at: '2026-02-01T00:00:00Z',
              created_at: '2026-01-25T00:00:00Z',
              updated_at: '2026-02-01T00:00:00Z',
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/governance/my-approvals', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ pending_approvals: [] }),
      });
    });

    await page.goto('/access-requests');

    // The fulfilled request should show expiry date indicator
    await expect(page.locator('text=Admin Role')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=fulfilled')).toBeVisible();

    // The expired request should show the expired status
    await expect(page.locator('text=Dev Group')).toBeVisible();
    await expect(page.locator('text=expired')).toBeVisible();
  });
});
