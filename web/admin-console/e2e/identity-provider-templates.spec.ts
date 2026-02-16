import { test, expect } from '@playwright/test';

test.describe('Identity Provider Quick Setup Templates', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/identity/providers*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'x-total-count': '0' },
          body: JSON.stringify([]),
        });
      } else if (route.request().method() === 'POST') {
        const body = JSON.parse(route.request().postData() || '{}');
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            id: 'new-provider-id',
            ...body,
            created_at: '2026-02-16T00:00:00Z',
            updated_at: '2026-02-16T00:00:00Z',
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.goto('/identity-providers');
  });

  test('should display Quick Setup section with provider cards', async ({ page }) => {
    await expect(page.getByText('Quick Setup')).toBeVisible();
    await expect(page.getByRole('button', { name: /Google/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /GitHub/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Microsoft Entra ID/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Custom OIDC/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Custom SAML/i })).toBeVisible();
  });

  test('should pre-fill form when clicking Google template', async ({ page }) => {
    await page.getByRole('button', { name: /Google/i }).click();

    await expect(page.getByRole('heading', { name: /Add Google Provider/i })).toBeVisible();
    await expect(page.locator('#name')).toHaveValue('Google');
    await expect(page.locator('#issuer_url')).toHaveValue('https://accounts.google.com');
    await expect(page.locator('#scopes')).toHaveValue(/openid.*profile.*email/);
    // Client ID and secret should be empty
    await expect(page.locator('#client_id')).toHaveValue('');
    await expect(page.locator('#client_secret')).toHaveValue('');
  });

  test('should pre-fill form when clicking Microsoft template', async ({ page }) => {
    await page.getByRole('button', { name: /Microsoft Entra ID/i }).click();

    await expect(page.getByRole('heading', { name: /Add Microsoft Entra ID Provider/i })).toBeVisible();
    await expect(page.locator('#name')).toHaveValue('Microsoft Entra ID');
    await expect(page.locator('#issuer_url')).toHaveValue(/login\.microsoftonline\.com/);
  });

  test('should pre-fill form when clicking GitHub template', async ({ page }) => {
    await page.getByRole('button', { name: /GitHub/i }).click();

    await expect(page.getByRole('heading', { name: /Add GitHub Provider/i })).toBeVisible();
    await expect(page.locator('#name')).toHaveValue('GitHub');
    await expect(page.locator('#issuer_url')).toHaveValue('https://github.com');
  });

  test('should show setup guide link for template providers', async ({ page }) => {
    await page.getByRole('button', { name: /Google/i }).click();

    const guideLink = page.getByRole('link', { name: /setup guide/i });
    await expect(guideLink).toBeVisible();
    await expect(guideLink).toHaveAttribute('href', /developers\.google\.com/);
    await expect(guideLink).toHaveAttribute('target', '_blank');
  });

  test('should open empty form for Custom OIDC', async ({ page }) => {
    await page.getByRole('button', { name: /Custom OIDC/i }).click();

    await expect(page.getByRole('heading', { name: /Add Identity Provider/i })).toBeVisible();
    await expect(page.locator('#name')).toHaveValue('');
    await expect(page.locator('#issuer_url')).toHaveValue('');
  });

  test('should open SAML form for Custom SAML', async ({ page }) => {
    await page.getByRole('button', { name: /Custom SAML/i }).click();

    await expect(page.getByRole('heading', { name: /Add Identity Provider/i })).toBeVisible();
    await expect(page.locator('#name')).toHaveValue('');
  });

  test('should submit provider from template with client credentials', async ({ page }) => {
    await page.getByRole('button', { name: /Google/i }).click();
    await page.locator('#client_id').fill('my-google-client-id');
    await page.locator('#client_secret').fill('my-google-client-secret');

    const requestPromise = page.waitForRequest((req) =>
      req.url().includes('/api/v1/identity/providers') && req.method() === 'POST'
    );
    await page.getByRole('button', { name: /Create/i }).click();
    const request = await requestPromise;
    const postedData = JSON.parse(request.postData() || '{}');

    expect(postedData.name).toBe('Google');
    expect(postedData.issuer_url).toBe('https://accounts.google.com');
    expect(postedData.client_id).toBe('my-google-client-id');
    expect(postedData.enabled).toBe(true);
  });
});
