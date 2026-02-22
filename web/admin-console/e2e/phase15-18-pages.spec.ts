import { test, expect } from '@playwright/test';

// ============================================================
// 1. MFA Management Page
// ============================================================

test.describe('MFA Management Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/mfa/enrollment-stats*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 200,
          mfa_enabled_count: 150,
          totp_count: 80,
          sms_count: 40,
          email_otp_count: 20,
          push_count: 5,
          webauthn_count: 5,
        }),
      });
    });

    await page.route('**/api/v1/mfa/policies*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          policies: [
            {
              id: '1',
              name: 'Enforce TOTP',
              description: 'Require TOTP for all users',
              enabled: true,
              priority: 1,
              conditions: {},
              required_methods: ['totp'],
              grace_period_hours: 24,
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          ],
          total: 1,
          page: 1,
          page_size: 20,
        }),
      });
    });

    await page.route('**/api/v1/mfa/user-status*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          users: [
            {
              user_id: 'u1',
              username: 'admin',
              email: 'admin@example.com',
              totp_enabled: true,
              sms_enabled: false,
              email_otp_enabled: false,
              push_enabled: false,
              webauthn_enabled: false,
            },
          ],
          total: 1,
          page: 1,
          page_size: 20,
        }),
      });
    });
  });

  test('should display MFA Management heading', async ({ page }) => {
    await page.goto('/mfa-management');
    await expect(page.locator('h1')).toContainText('MFA Management');
  });

  test('should display enrollment stats cards', async ({ page }) => {
    await page.goto('/mfa-management');
    await expect(page.locator('h1')).toContainText('MFA Management');
    await expect(page.getByText('Total Users')).toBeVisible();
    await expect(page.getByText('MFA Enabled')).toBeVisible();
    await expect(page.getByText('TOTP Enrolled')).toBeVisible();
  });

  test('should display tabs', async ({ page }) => {
    await page.goto('/mfa-management');
    await expect(page.locator('h1')).toContainText('MFA Management');
    await expect(page.getByText('Enrollment Overview')).toBeVisible();
    await expect(page.getByText('MFA Policies')).toBeVisible();
    await expect(page.getByText('User MFA Status')).toBeVisible();
  });
});

// ============================================================
// 2. Login Anomalies Page
// ============================================================

test.describe('Login Anomalies Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/risk/overview*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          avg_risk_score: 35.2,
          high_risk_count: 12,
          total_logins_7d: 540,
          risk_distribution: {
            low: 400,
            medium: 100,
            high: 30,
            critical: 10,
          },
        }),
      });
    });

    await page.route('**/api/v1/risk/anomalies*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          anomalies: [
            {
              id: 'a1',
              user_id: 'u1',
              username: 'suspicious_user',
              ip_address: '10.0.0.1',
              user_agent: 'Mozilla/5.0',
              location: 'Unknown',
              risk_score: 85,
              success: false,
              auth_methods: ['password'],
              created_at: '2024-01-20T10:00:00Z',
            },
          ],
          total: 1,
          page: 1,
          page_size: 20,
        }),
      });
    });

    await page.route('**/api/v1/risk/user-profile/*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          user_id: 'u1',
          username: 'suspicious_user',
          baseline: {
            typical_login_hours: [9, 10, 11],
            typical_countries: ['US'],
            typical_ips: ['192.168.1.1'],
            avg_risk_score: 20,
            login_count: 50,
          },
          recent_logins: [],
        }),
      });
    });
  });

  test('should display Login Anomalies heading', async ({ page }) => {
    await page.goto('/login-anomalies');
    await expect(page.locator('h1')).toContainText('Login Anomalies');
  });

  test('should display overview cards', async ({ page }) => {
    await page.goto('/login-anomalies');
    await expect(page.locator('h1')).toContainText('Login Anomalies');
    await expect(page.getByText('Average Risk Score')).toBeVisible();
    await expect(page.getByText('High-Risk Logins (7d)')).toBeVisible();
    await expect(page.getByText('Total Logins (7d)')).toBeVisible();
    await expect(page.getByText('Risk Distribution')).toBeVisible();
  });

  test('should display anomalies table', async ({ page }) => {
    await page.goto('/login-anomalies');
    await expect(page.locator('h1')).toContainText('Login Anomalies');
    await expect(page.getByText('Recent Anomalies')).toBeVisible();
    await expect(page.getByText('suspicious_user')).toBeVisible();
  });
});

// ============================================================
// 3. Notification Admin Page
// ============================================================

test.describe('Notification Admin Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/admin/notifications/routing-rules*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'r1',
              name: 'Security Alerts',
              event_type: 'security_alert',
              conditions: {},
              channels: ['in_app', 'email'],
              template_overrides: {},
              priority: 1,
              enabled: true,
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/notifications/broadcasts*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'b1',
              title: 'Maintenance Window',
              body: 'Scheduled maintenance tonight',
              channel: 'in_app',
              target_type: 'all',
              target_ids: [],
              priority: 'normal',
              scheduled_at: '',
              sent_at: '',
              status: 'draft',
              total_recipients: 100,
              delivered_count: 0,
              read_count: 0,
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/notifications/stats*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_sent: 500,
          total_read: 350,
          total_unread: 150,
          channel_breakdown: { in_app: 300, email: 200 },
          routing_rules_count: 3,
        }),
      });
    });
  });

  test('should display Notification Administration heading', async ({ page }) => {
    await page.goto('/notification-admin');
    await expect(page.locator('h1')).toContainText('Notification Administration');
  });

  test('should display tabs', async ({ page }) => {
    await page.goto('/notification-admin');
    await expect(page.locator('h1')).toContainText('Notification Administration');
    await expect(page.getByText('Routing Rules')).toBeVisible();
    await expect(page.getByText('Broadcasts')).toBeVisible();
    await expect(page.getByText('Delivery Stats')).toBeVisible();
  });
});

// ============================================================
// 4. Notification Center Page
// ============================================================

test.describe('Notification Center Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/notifications/history*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'n1',
              type: 'security',
              channel: 'in_app',
              title: 'New Login Detected',
              body: 'A new login was detected from an unknown device.',
              link: '',
              read: false,
              metadata: {},
              created_at: new Date().toISOString(),
            },
            {
              id: 'n2',
              type: 'system',
              channel: 'in_app',
              title: 'System Update',
              body: 'System has been updated to the latest version.',
              link: '',
              read: true,
              metadata: {},
              created_at: new Date(Date.now() - 86400000).toISOString(),
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/notifications/digest*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            { id: 'd1', digest_type: 'daily', channel: 'email', enabled: true },
            { id: 'd2', digest_type: 'weekly', channel: 'email', enabled: false },
          ],
        }),
      });
    });

    await page.route('**/api/v1/notifications/mark-read*', async (route) => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });

    await page.route('**/api/v1/notifications/*', async (route) => {
      if (route.request().method() === 'DELETE') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
      } else {
        await route.continue();
      }
    });
  });

  test('should display Notification Center heading', async ({ page }) => {
    await page.goto('/notification-center');
    await expect(page.locator('h1')).toContainText('Notification Center');
  });

  test('should display notification list', async ({ page }) => {
    await page.goto('/notification-center');
    await expect(page.locator('h1')).toContainText('Notification Center');
    await expect(page.getByText('New Login Detected')).toBeVisible();
    await expect(page.getByText('System Update')).toBeVisible();
  });
});

// ============================================================
// 5. Tenant Management Page
// ============================================================

test.describe('Tenant Management Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/admin/organizations*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            { id: 'org-1', name: 'Acme Corp', slug: 'acme' },
            { id: 'org-2', name: 'Tech Inc', slug: 'tech' },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/tenants/*/branding*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          logo_url: '',
          favicon_url: '',
          primary_color: '#3b82f6',
          secondary_color: '#6366f1',
          background_color: '#f8fafc',
          background_image_url: '',
          login_page_title: 'Sign In',
          login_page_message: 'Welcome back.',
          portal_title: 'Admin Portal',
          custom_css: '',
          custom_footer: '',
          powered_by_visible: true,
        }),
      });
    });

    await page.route('**/api/v1/admin/tenants/*/settings*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          security: {},
          authentication: {},
          session: {},
        }),
      });
    });

    await page.route('**/api/v1/admin/tenants/*/domains*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'd1',
              domain: 'login.acme.com',
              domain_type: 'custom',
              verified: true,
              primary_domain: true,
            },
          ],
        }),
      });
    });
  });

  test('should display Tenant Management heading', async ({ page }) => {
    await page.goto('/tenant-management');
    await expect(page.locator('h1')).toContainText('Tenant Management');
  });

  test('should display tabs after selecting an organization', async ({ page }) => {
    await page.goto('/tenant-management');
    await expect(page.locator('h1')).toContainText('Tenant Management');
    // The first org is auto-selected, so tabs should appear
    await expect(page.getByText('Branding')).toBeVisible();
    await expect(page.getByText('Settings')).toBeVisible();
    await expect(page.getByText('Domains')).toBeVisible();
  });
});

// ============================================================
// 6. Privacy Dashboard Page
// ============================================================

test.describe('Privacy Dashboard Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/admin/privacy/dashboard*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_consents: 1200,
          active_dsars: 8,
          overdue_dsars: 2,
          total_assessments: 5,
          consent_breakdown: [
            { consent_type: 'marketing', granted: 800, revoked: 50 },
            { consent_type: 'analytics', granted: 600, revoked: 100 },
          ],
          recent_dsars: [
            {
              id: 'dsar-1',
              request_type: 'export',
              status: 'in_progress',
              username: 'john.doe',
              created_at: '2024-01-15T00:00:00Z',
            },
            {
              id: 'dsar-2',
              request_type: 'delete',
              status: 'pending',
              username: 'jane.smith',
              created_at: '2024-01-18T00:00:00Z',
            },
          ],
        }),
      });
    });
  });

  test('should display Privacy Dashboard heading', async ({ page }) => {
    await page.goto('/privacy-dashboard');
    await expect(page.locator('h1')).toContainText('Privacy Dashboard');
  });

  test('should display summary cards', async ({ page }) => {
    await page.goto('/privacy-dashboard');
    await expect(page.locator('h1')).toContainText('Privacy Dashboard');
    await expect(page.getByText('Total Consents')).toBeVisible();
    await expect(page.getByText('Active DSARs')).toBeVisible();
    await expect(page.getByText('Overdue DSARs')).toBeVisible();
    await expect(page.getByText('Impact Assessments')).toBeVisible();
  });
});

// ============================================================
// 7. Consent Management Page
// ============================================================

test.describe('Consent Management Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/admin/privacy/consents*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'c1',
              user_id: 'u1',
              username: 'john.doe',
              consent_type: 'marketing',
              version: '1.0',
              granted: true,
              granted_at: '2024-01-10T00:00:00Z',
              revoked_at: null,
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/privacy/dsars*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'dsar-1',
              user_id: 'u1',
              username: 'john.doe',
              request_type: 'export',
              status: 'pending',
              reason: 'GDPR request',
              due_date: '2024-02-10T00:00:00Z',
              created_at: '2024-01-10T00:00:00Z',
              completed_at: null,
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/privacy/retention*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'ret-1',
              name: 'Audit Log Retention',
              data_category: 'audit_logs',
              retention_days: 365,
              action: 'delete',
              enabled: true,
              created_at: '2024-01-01T00:00:00Z',
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/privacy/assessments*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'assess-1',
              title: 'User Analytics Assessment',
              description: 'Assessment of user analytics processing',
              risk_level: 'medium',
              status: 'in_review',
              assessor: 'admin',
              data_categories: ['behavioral_data'],
              processing_purposes: ['analytics'],
              created_at: '2024-01-05T00:00:00Z',
            },
          ],
        }),
      });
    });
  });

  test('should display Consent Management heading', async ({ page }) => {
    await page.goto('/consent-management');
    await expect(page.locator('h1')).toContainText('Consent Management');
  });

  test('should display tabs', async ({ page }) => {
    await page.goto('/consent-management');
    await expect(page.locator('h1')).toContainText('Consent Management');
    await expect(page.getByText('User Consents')).toBeVisible();
    await expect(page.getByText('Data Subject Requests')).toBeVisible();
    await expect(page.getByText('Retention Policies')).toBeVisible();
    await expect(page.getByText('Impact Assessments')).toBeVisible();
  });
});

// ============================================================
// 8. Federation Config Page
// ============================================================

test.describe('Federation Config Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/admin/federation/rules*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'fr1',
              name: 'Corporate Google SSO',
              email_domain: 'company.com',
              provider_id: 'p1',
              provider_name: 'Google Workspace',
              priority: 1,
              auto_redirect: true,
              enabled: true,
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/identity/providers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'p1', name: 'Google Workspace' },
          { id: 'p2', name: 'Azure AD' },
        ]),
      });
    });

    await page.route('**/api/v1/admin/applications*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            { id: 'app1', name: 'Admin Console' },
            { id: 'app2', name: 'API Gateway' },
          ],
        }),
      });
    });

    await page.route('**/api/v1/admin/users/*/identity-links*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.route('**/api/v1/admin/applications/*/claims*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });
  });

  test('should display Federation Configuration heading', async ({ page }) => {
    await page.goto('/federation-config');
    await expect(page.locator('h1')).toContainText('Federation Configuration');
  });

  test('should display tabs', async ({ page }) => {
    await page.goto('/federation-config');
    await expect(page.locator('h1')).toContainText('Federation Configuration');
    await expect(page.getByText('Federation Rules')).toBeVisible();
    await expect(page.getByText('Identity Links')).toBeVisible();
    await expect(page.getByText('Claims Mapping')).toBeVisible();
  });
});

// ============================================================
// 9. Social Providers Page
// ============================================================

test.describe('Social Providers Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/v1/admin/social-providers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: [
            {
              id: 'sp1',
              provider_id: 'p1',
              provider_key: 'google',
              display_name: 'Google',
              icon_url: '',
              button_color: '#4285F4',
              button_text: 'Sign in with Google',
              auto_create_users: true,
              auto_link_by_email: true,
              default_role: 'user',
              allowed_domains: ['example.com'],
              attribute_mapping: {},
              enabled: true,
              sort_order: 0,
            },
            {
              id: 'sp2',
              provider_id: 'p2',
              provider_key: 'github',
              display_name: 'GitHub',
              icon_url: '',
              button_color: '#24292e',
              button_text: 'Sign in with GitHub',
              auto_create_users: false,
              auto_link_by_email: false,
              default_role: 'user',
              allowed_domains: [],
              attribute_mapping: {},
              enabled: false,
              sort_order: 1,
            },
          ],
        }),
      });
    });
  });

  test('should display Social Login Providers heading', async ({ page }) => {
    await page.goto('/social-providers');
    await expect(page.locator('h1')).toContainText('Social Login Providers');
  });

  test('should display provider list', async ({ page }) => {
    await page.goto('/social-providers');
    await expect(page.locator('h1')).toContainText('Social Login Providers');
    await expect(page.getByText('Google').first()).toBeVisible();
    await expect(page.getByText('GitHub').first()).toBeVisible();
  });

  test('should show empty state when no providers', async ({ page }) => {
    await page.route('**/api/v1/admin/social-providers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: [] }),
      });
    });

    await page.goto('/social-providers');
    await expect(page.locator('h1')).toContainText('Social Login Providers');
    await expect(page.getByText('No social providers configured')).toBeVisible();
  });
});
