import { test, expect } from '@playwright/test';

test.describe('API Documentation Page', () => {
  test('should display the API documentation page', async ({ page }) => {
    await page.goto('/api-docs');

    await expect(page.getByRole('heading', { name: /API Documentation/i })).toBeVisible();
    await expect(page.getByText('Interactive API Reference')).toBeVisible();
  });

  test('should show service tabs', async ({ page }) => {
    await page.goto('/api-docs');

    await expect(page.getByRole('tab', { name: /Identity/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /OAuth/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Admin/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Access/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Governance/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Audit/i })).toBeVisible();
  });

  test('should load Swagger UI for default service', async ({ page }) => {
    await page.goto('/api-docs');

    // Swagger UI renders with this class
    await expect(page.locator('.swagger-ui')).toBeVisible({ timeout: 15000 });
  });

  test('should switch between service specs', async ({ page }) => {
    await page.goto('/api-docs');

    // Wait for initial load
    await expect(page.locator('.swagger-ui')).toBeVisible({ timeout: 15000 });

    // Click on Governance tab
    await page.getByRole('tab', { name: /Governance/i }).click();

    // Swagger UI should still be visible
    await expect(page.locator('.swagger-ui')).toBeVisible({ timeout: 15000 });
  });

  test('should be accessible from sidebar navigation', async ({ page }) => {
    await page.goto('/dashboard');

    // Mock dashboard API to avoid errors
    await page.route('**/api/v1/dashboard*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ total_users: 0, total_groups: 0, total_applications: 0, active_sessions: 0 }),
      });
    });

    const apiDocsLink = page.locator('a[href="/api-docs"]');
    await expect(apiDocsLink).toBeVisible({ timeout: 10000 });
    await apiDocsLink.click();
    await expect(page).toHaveURL('/api-docs');
  });
});
