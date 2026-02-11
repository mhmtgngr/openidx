import { test, expect } from '@playwright/test';

const mockPlatformCert = {
  cert_type: 'custom',
  subject: 'CN=*.openidx.local,O=OpenIDX',
  issuer: 'CN=OpenIDX CA,O=OpenIDX',
  not_before: '2024-06-01T00:00:00Z',
  not_after: '2025-12-01T00:00:00Z',
  days_left: 180,
  fingerprint: 'ab12cd34ef56789012345678901234567890abcdef1234567890abcdef12345678',
  sans: ['*.openidx.local', 'localhost', '127.0.0.1'],
  serial_number: '1234567890ABCDEF',
  uploaded_at: '2024-06-01T10:00:00Z',
  consumers: [
    { name: 'BrowZer Bootstrapper', port: 443, protocol: 'HTTPS', status: 'active', description: 'Serves the BrowZer SDK to browsers', restart_hint: 'Auto-restarts on cert change' },
    { name: 'OAuth TLS Proxy', port: 8446, protocol: 'HTTPS', status: 'active', description: 'TLS termination for OpenIDX OAuth service', restart_hint: 'docker restart openidx-oauth-tls-proxy' },
    { name: 'Ziti Controller Proxy', port: 1280, protocol: 'HTTPS', status: 'active', description: 'TLS termination for Ziti management plane', restart_hint: 'docker restart openidx-ziti-controller-proxy' },
    { name: 'Ziti Router (WSS)', port: 3023, protocol: 'WSS', status: 'active', description: 'WebSocket Secure listener for BrowZer data plane', restart_hint: 'docker restart openidx-ziti-router' },
    { name: 'APISIX Gateway', port: 8443, protocol: 'HTTPS', status: 'active', description: 'API Gateway HTTPS endpoint', restart_hint: 'APISIX auto-reloads on config change' },
  ],
};

const mockApisixEnabled = {
  enabled: true,
  last_updated: '2024-06-15T14:30:00Z',
  cert_fingerprint: 'ab12cd34ef56789012345678901234567890abcdef1234567890abcdef12345678',
};

const mockApisixDisabled = {
  enabled: false,
  last_updated: '',
  cert_fingerprint: '',
};

const mockExpiryAlerts = [
  { source: 'platform', name: 'Platform TLS Certificate', days_left: 15, severity: 'warning', not_after: '2025-06-01T00:00:00Z' },
];

const mockCertStatus = {
  platform: mockPlatformCert,
  apisix: mockApisixEnabled,
  expiry_alerts: mockExpiryAlerts,
};

const mockZitiCerts = [
  { id: 'ziti-1', name: 'Root CA', cert_type: 'ca', subject: 'CN=Ziti Root CA', issuer: 'CN=Ziti Root CA', fingerprint: 'abc123def456', not_before: '2024-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z', auto_renew: true, status: 'valid', days_until_expiry: 365 },
  { id: 'ziti-2', name: 'Edge Controller', cert_type: 'server', subject: 'CN=edge-controller', issuer: 'CN=Ziti Root CA', fingerprint: 'xyz789uvw012', not_before: '2024-06-01T00:00:00Z', not_after: '2025-01-15T00:00:00Z', auto_renew: false, status: 'valid', days_until_expiry: 25 },
  { id: 'ziti-3', name: 'Edge Router', cert_type: 'server', subject: 'CN=edge-router', issuer: 'CN=Ziti Root CA', fingerprint: 'mno345pqr678', not_before: '2024-03-01T00:00:00Z', not_after: '2025-09-01T00:00:00Z', auto_renew: true, status: 'valid', days_until_expiry: 200 },
];

test.describe('Certificates Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockCertStatus),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockZitiCerts),
        });
      }
    });
  });

  test('should display certificates page heading', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('h1:has-text("Certificate Management")')).toBeVisible();
    await expect(page.locator('text=Manage TLS certificates across the OpenIDX platform')).toBeVisible();
  });

  test('should have all three tabs', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.getByRole('tab', { name: /platform tls/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /api gateway/i })).toBeVisible();
    await expect(page.getByRole('tab', { name: /ziti certificates/i })).toBeVisible();
  });

  test('should display expiry alert banner when certificates are expiring', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=Platform TLS Certificate').first()).toBeVisible();
    await expect(page.locator('text=15 days').first()).toBeVisible();
  });

  test('should not display expiry alert banner when no alerts', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockCertStatus, expiry_alerts: [] }),
      });
    });

    await page.goto('/certificates');

    await expect(page.locator('h1:has-text("Certificate Management")')).toBeVisible();
    await expect(page.locator('text=expires in')).not.toBeVisible();
  });
});

test.describe('Certificates Page - Platform TLS Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockCertStatus),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockZitiCerts),
        });
      }
    });
  });

  test('should display certificate type badge', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=CA-Signed').first()).toBeVisible();
  });

  test('should display certificate subject and issuer', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=CN=*.openidx.local,O=OpenIDX')).toBeVisible();
    await expect(page.locator('text=CN=OpenIDX CA,O=OpenIDX')).toBeVisible();
  });

  test('should display certificate expiry with days left', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=180 days left')).toBeVisible();
  });

  test('should display subject alternative names', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.getByText('*.openidx.local', { exact: true }).first()).toBeVisible();
    await expect(page.locator('text=localhost').first()).toBeVisible();
    await expect(page.locator('text=127.0.0.1')).toBeVisible();
  });

  test('should display SHA-256 fingerprint', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=ab12cd34ef5678')).toBeVisible();
  });

  test('should display certificate consumers', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=BrowZer Bootstrapper').first()).toBeVisible();
    await expect(page.locator('text=OAuth TLS Proxy').first()).toBeVisible();
    await expect(page.locator('text=Ziti Controller Proxy').first()).toBeVisible();
    await expect(page.locator('text=Ziti Router (WSS)').first()).toBeVisible();
    await expect(page.locator('text=APISIX Gateway').first()).toBeVisible();
  });

  test('should display upload certificate section', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=Upload Custom Certificate')).toBeVisible();
    await expect(page.getByRole('button', { name: /upload certificate/i })).toBeVisible();
  });

  test('should show Revert to Self-Signed button when custom cert is active', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.getByRole('button', { name: /revert to self-signed/i })).toBeVisible();
  });

  test('should not show Revert button when using self-signed cert', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ...mockCertStatus,
          platform: { ...mockPlatformCert, cert_type: 'self_signed', uploaded_at: null },
        }),
      });
    });

    await page.goto('/certificates');

    await expect(page.locator('text=Self-Signed').first()).toBeVisible();
    await expect(page.getByRole('button', { name: /revert to self-signed/i })).not.toBeVisible();
  });

  test('should show success toast on certificate upload', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/platform', async (route) => {
      if (route.request().method() === 'POST') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Certificate uploaded successfully' }),
        });
      }
    });

    await page.goto('/certificates');

    // Set mock files on the file inputs
    const certContent = Buffer.from('-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----');
    const keyContent = Buffer.from('-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----');

    const fileInputs = page.locator('input[type="file"]');
    await fileInputs.first().setInputFiles({ name: 'cert.pem', mimeType: 'application/x-pem-file', buffer: certContent });
    await fileInputs.nth(1).setInputFiles({ name: 'key.pem', mimeType: 'application/x-pem-file', buffer: keyContent });

    await page.getByRole('button', { name: /upload certificate/i }).click();

    await expect(page.locator('text=Certificate uploaded').first()).toBeVisible();
  });

  test('should show success toast on revert to self-signed', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/platform', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Reverted to self-signed certificate' }),
        });
      }
    });

    await page.goto('/certificates');

    await page.getByRole('button', { name: /revert to self-signed/i }).click();

    await expect(page.locator('text=Reverted to self-signed certificate').first()).toBeVisible();
  });

  test('should display post-change instructions', async ({ page }) => {
    await page.goto('/certificates');

    await expect(page.locator('text=After Certificate Changes')).toBeVisible();
    await expect(page.locator('text=docker restart')).toBeVisible();
  });
});

test.describe('Certificates Page - API Gateway Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockCertStatus),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockZitiCerts),
        });
      }
    });
  });

  test('should display APISIX HTTPS heading', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.locator('text=APISIX HTTPS')).toBeVisible();
  });

  test('should display Enabled badge when APISIX SSL is enabled', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.locator('text=Enabled').first()).toBeVisible();
  });

  test('should display HTTP and HTTPS endpoints', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.locator('text=http://localhost:8088')).toBeVisible();
    await expect(page.locator('text=https://localhost:8443')).toBeVisible();
  });

  test('should show Disable HTTPS button when enabled', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.getByRole('button', { name: /disable https/i })).toBeVisible();
  });

  test('should show Enable HTTPS button when disabled', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockCertStatus, apisix: mockApisixDisabled }),
      });
    });

    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.getByRole('button', { name: /enable https/i })).toBeVisible();
  });

  test('should show Not configured when APISIX is disabled', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockCertStatus, apisix: mockApisixDisabled }),
      });
    });

    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.locator('text=Not configured')).toBeVisible();
  });

  test('should show success toast on enabling APISIX HTTPS', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ...mockCertStatus, apisix: mockApisixDisabled }),
      });
    });

    await page.route('**/api/v1/access/certificates/apisix/enable', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'APISIX HTTPS enabled on port 8443', hint: 'Available at https://localhost:8443' }),
      });
    });

    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await page.getByRole('button', { name: /enable https/i }).click();

    await expect(page.locator('text=APISIX HTTPS enabled').first()).toBeVisible();
  });

  test('should show success toast on disabling APISIX HTTPS', async ({ page }) => {
    await page.route('**/api/v1/access/certificates/apisix/disable', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'APISIX HTTPS disabled' }),
      });
    });

    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await page.getByRole('button', { name: /disable https/i }).click();

    await expect(page.locator('text=APISIX HTTPS disabled').first()).toBeVisible();
  });

  test('should display How it works section', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /api gateway/i }).click();

    await expect(page.locator('text=How it works')).toBeVisible();
    await expect(page.locator('text=Enabling HTTPS injects')).toBeVisible();
  });
});

test.describe('Certificates Page - Ziti Certificates Tab', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockCertStatus),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockZitiCerts),
        });
      }
    });
  });

  test('should display Ziti Internal Certificates heading', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await expect(page.locator('text=Ziti Internal Certificates')).toBeVisible();
  });

  test('should display certificate table with correct columns', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await expect(page.locator('th:has-text("Name")')).toBeVisible();
    await expect(page.locator('th:has-text("Type")')).toBeVisible();
    await expect(page.locator('th:has-text("Subject")')).toBeVisible();
    await expect(page.locator('th:has-text("Expiry")')).toBeVisible();
    await expect(page.locator('th:has-text("Auto Renew")')).toBeVisible();
  });

  test('should display all Ziti certificates in the table', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await expect(page.getByRole('cell', { name: 'Root CA', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Edge Controller', exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: 'Edge Router', exact: true })).toBeVisible();
  });

  test('should display cert type badges', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await expect(page.locator('td').filter({ hasText: /^ca$/ }).first()).toBeVisible();
    await expect(page.locator('td').filter({ hasText: /^server$/ }).first()).toBeVisible();
  });

  test('should show expiring soon alert for certs within 30 days', async ({ page }) => {
    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await expect(page.locator('text=Certificates Expiring Soon')).toBeVisible();
    await expect(page.locator('text=Edge Controller').first()).toBeVisible();
  });

  test('should show success toast on certificate rotation', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/certificates/*/rotate', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Certificate rotated' }),
      });
    });

    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await page.getByRole('button', { name: /rotate/i }).first().click();

    await expect(page.locator('text=Certificate rotated').first()).toBeVisible();
  });

  test('should display empty state when no Ziti certificates', async ({ page }) => {
    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify([]),
        });
      }
    });

    await page.goto('/certificates');
    await page.getByRole('tab', { name: /ziti certificates/i }).click();

    await expect(page.locator('text=No Ziti certificates found')).toBeVisible();
  });
});

test.describe('Certificates Page - Navigation', () => {
  test('should navigate to certificates page from sidebar', async ({ page }) => {
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

    await page.route('**/api/v1/access/certificates/status', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(mockCertStatus),
      });
    });

    await page.route('**/api/v1/access/ziti/certificates', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(mockZitiCerts),
        });
      }
    });

    await page.goto('/dashboard');

    await page.locator('a[href="/certificates"]').click();

    await expect(page).toHaveURL(/\/certificates/);
    await expect(page.locator('h1:has-text("Certificate Management")')).toBeVisible();
  });
});
