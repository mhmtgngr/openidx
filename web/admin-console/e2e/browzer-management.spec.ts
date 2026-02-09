import { test, expect } from '@playwright/test';

const mockBrowzerStatus = {
  browzer_enabled: true,
  domain: 'browzer.localtest.me',
  bootstrapper_url: 'https://browzer.localtest.me/',
  cert_type: 'self_signed',
  cert_subject: 'CN=browzer.localtest.me',
  cert_issuer: 'CN=OpenIDX Self-Signed CA',
  cert_not_after: '2025-12-01T00:00:00Z',
  cert_fingerprint: 'aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233',
  cert_san: ['browzer.localtest.me', '*.browzer.localtest.me'],
  cert_days_left: 180,
  targets_count: 2,
  targets: [
    { vhost: 'app1.browzer.localtest.me', service: 'web-app', path: '/', scheme: 'https' },
    { vhost: 'app2.browzer.localtest.me', service: 'api-server', path: '/', scheme: 'https' },
  ],
  domain_config: {
    domain: 'browzer.localtest.me',
    cert_type: 'self_signed',
    cert_subject: 'CN=browzer.localtest.me',
    cert_issuer: 'CN=OpenIDX Self-Signed CA',
    cert_not_before: '2024-06-01T00:00:00Z',
    cert_not_after: '2025-12-01T00:00:00Z',
    cert_fingerprint: 'aa11bb22cc33dd44',
    cert_san: ['browzer.localtest.me'],
    custom_cert_uploaded_at: null,
    previous_domain: 'browzer.old-domain.com',
    domain_changed_at: '2024-05-15T09:00:00Z',
  },
};

test.describe('BrowZer Management Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockBrowzerStatus),
      });
    });
  });

  test('should display page heading', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.locator('h1:has-text("BrowZer Bootstrapper Management")')).toBeVisible();
    await expect(page.locator('text=Manage TLS certificates, domain, and bootstrapper lifecycle')).toBeVisible();
  });

  test('should display Enabled status badge', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.locator('text=Enabled').first()).toBeVisible();
  });

  test('should display Disabled status badge when BrowZer is disabled', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockBrowzerStatus, browzer_enabled: false }),
      });
    });

    await page.goto('/browzer-management');

    await expect(page.locator('text=Disabled').first()).toBeVisible();
  });

  test('should have all three tabs', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.getByRole('tab', { name: /overview/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /certificates/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /domain/i })).toBeVisible();
  });

  test('should display cert expiry warning when cert is expiring soon', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockBrowzerStatus, cert_days_left: 15 }),
      });
    });

    await page.goto('/browzer-management');

    await expect(page.locator('text=expires in')).toBeVisible();
    await expect(page.locator('text=15 days')).toBeVisible();
  });

  test('should not display cert expiry warning when cert is healthy', async ({ page }) => {
    await page.goto('/browzer-management');

    // 180 days is well above 30-day threshold
    await expect(page.locator('text=Certificate expires in')).not.toBeVisible();
  });
});

test.describe('BrowZer Management - Overview Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockBrowzerStatus),
      });
    });
  });

  test('should display Status card with BrowZer status and domain', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.locator('text=browzer.localtest.me').first()).toBeVisible();
  });

  test('should display bootstrapper URL', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.locator('text=https://browzer.localtest.me/')).toBeVisible();
  });

  test('should display Certificate summary card', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.locator('text=Self-Signed').first()).toBeVisible();
  });

  test('should display Targets card with count and details', async ({ page }) => {
    await page.goto('/browzer-management');

    await expect(page.locator('text=2').first()).toBeVisible();
    await expect(page.locator('text=Active bootstrapper targets')).toBeVisible();
    await expect(page.locator('text=app1.browzer.localtest.me')).toBeVisible();
    await expect(page.locator('text=app2.browzer.localtest.me')).toBeVisible();
    await expect(page.locator('text=web-app')).toBeVisible();
    await expect(page.locator('text=api-server')).toBeVisible();
  });

  test('should show success toast on restart', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/restart', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Restart triggered' }),
      });
    });

    await page.goto('/browzer-management');

    await page.getByRole('button', { name: /restart bootstrapper/i }).click();

    await expect(page.locator('text=Restart triggered').first()).toBeVisible();
  });

  test('should show error toast on restart failure', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/restart', async (route) => {
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Service unavailable' }),
      });
    });

    await page.goto('/browzer-management');

    await page.getByRole('button', { name: /restart bootstrapper/i }).click();

    await expect(page.locator('text=Restart failed').first()).toBeVisible();
  });
});

test.describe('BrowZer Management - Certificates Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockBrowzerStatus),
      });
    });
  });

  test('should display BrowZer Certificate heading', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /certificates/i }).click();

    await expect(page.locator('text=BrowZer Certificate')).toBeVisible();
  });

  test('should display certificate type and issuer', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /certificates/i }).click();

    await expect(page.locator('text=Self-Signed').first()).toBeVisible();
  });

  test('should display centralized management text', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /certificates/i }).click();

    await expect(page.locator('text=Platform certificates are managed centrally')).toBeVisible();
  });

  test('should have Manage Certificates button that navigates to /certificates', async ({ page }) => {
    // Mock the certificates page routes for navigation target
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ platform: null, apisix: null, expiry_alerts: [] }),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      }
    });

    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /certificates/i }).click();

    await page.getByRole('button', { name: /manage certificates/i }).click();

    await expect(page).toHaveURL(/\/certificates/);
  });
});

test.describe('BrowZer Management - Domain Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockBrowzerStatus),
      });
    });
  });

  test('should display current domain', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await expect(page.locator('text=Current Domain')).toBeVisible();
    await expect(page.locator('text=browzer.localtest.me').first()).toBeVisible();
  });

  test('should display previous domain info', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await expect(page.locator('text=browzer.old-domain.com')).toBeVisible();
  });

  test('should have domain input field with placeholder', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await expect(page.getByPlaceholder('e.g. browzer.tdv.org')).toBeVisible();
  });

  test('should disable Save Domain button when input is empty', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await expect(page.getByRole('button', { name: /save domain/i })).toBeDisabled();
  });

  test('should enable Save Domain button when domain is entered', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await page.getByPlaceholder('e.g. browzer.tdv.org').fill('browzer.newdomain.com');

    await expect(page.getByRole('button', { name: /save domain/i })).toBeEnabled();
  });

  test('should display cascading updates warning box', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await expect(page.locator('text=Important: Cascading Updates')).toBeVisible();
    await expect(page.locator('text=All BrowZer proxy routes will be updated')).toBeVisible();
  });

  test('should show success toast on domain change', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/domain', async (route) => {
      if (route.request().method() === 'PUT') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Domain changed successfully' }),
        });
      }
    });

    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await page.getByPlaceholder('e.g. browzer.tdv.org').fill('browzer.newdomain.com');
    await page.getByRole('button', { name: /save domain/i }).click();

    await expect(page.locator('text=Domain changed').first()).toBeVisible();
  });

  test('should show error toast on domain change failure', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/browzer/domain', async (route) => {
      if (route.request().method() === 'PUT') {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Internal server error' }),
        });
      }
    });

    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await page.getByPlaceholder('e.g. browzer.tdv.org').fill('browzer.newdomain.com');
    await page.getByRole('button', { name: /save domain/i }).click();

    await expect(page.locator('text=Domain change failed').first()).toBeVisible();
  });

  test('should display After Domain Change instructions', async ({ page }) => {
    await page.goto('/browzer-management');
    await page.getByRole('tab', { name: /domain/i }).click();

    await expect(page.locator('text=After Domain Change')).toBeVisible();
    await expect(page.locator('text=docker restart')).toBeVisible();
  });
});

test.describe('BrowZer Management - Navigation', () => {
  test('should navigate to BrowZer management page from sidebar', async ({ page }) => {
    // Mock dashboard API for initial page
    await page.route('**/api/v1/dashboard*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ total_users: 10, active_users: 5, total_groups: 2, total_applications: 1, active_sessions: 3, recent_logins: 15, security_alerts: 0 }),
      });
    });

    await page.route('**/api/v1/audit/events*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([]),
      });
    });

    await page.route('**/api/v1/access/ziti/browzer/management', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockBrowzerStatus),
      });
    });

    await page.goto('/dashboard');

    await page.locator('a[href="/browzer-management"]').click();

    await expect(page).toHaveURL(/\/browzer-management/);
    await expect(page.locator('h1:has-text("BrowZer Bootstrapper Management")')).toBeVisible();
  });
});
