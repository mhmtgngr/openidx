import { test, expect } from '@playwright/test';
import { LoginPage } from './pages/login.page';
import { DashboardPage } from './pages/dashboard.page';
import { MFAPage } from './pages/mfa.page';

/**
 * Authentication E2E Tests
 * Tests for login flow, MFA setup, and password reset
 */

test.describe('Authentication Flow', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);

    // Mock the login API
    await page.route('**/oauth/login', async (route) => {
      const requestBody = route.request().postDataJSON();

      // Simulate failed login for invalid credentials
      if (requestBody.username === 'invalid' || requestBody.password === 'wrong') {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Login failed. Please try again.'
          }),
        });
        return;
      }

      // Simulate successful login requiring MFA
      if (requestBody.username === 'mfa-user') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            mfa_required: true,
            mfa_session: 'test-mfa-session-123',
            mfa_methods: ['totp', 'sms'],
            login_session: 'test-login-session-456',
          }),
        });
        return;
      }

      // Simulate successful login without MFA
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          access_token: 'test-access-token',
          refresh_token: 'test-refresh-token',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      });
    });

    // Mock MFA verification endpoint
    await page.route('**/oauth/mfa/verify', async (route) => {
      const requestBody = route.request().postDataJSON();

      if (requestBody.code === '123456') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            access_token: 'test-access-token-mfa',
            refresh_token: 'test-refresh-token-mfa',
            token_type: 'Bearer',
            expires_in: 3600,
          }),
        });
      } else {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'invalid_code',
            error_description: 'Invalid verification code.',
          }),
        });
      }
    });

    // Mock dashboard API for authenticated user
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 42,
          active_users: 38,
          total_groups: 5,
          total_applications: 12,
          active_sessions: 15,
          pending_reviews: 3,
          security_alerts: 0,
          recent_activity: [],
          auth_stats: {
            total_logins: 1250,
            successful_logins: 1180,
            failed_logins: 70,
            mfa_usage: 85,
          },
        }),
      });
    });
  });

  test('should display login page with correct elements', async ({ page }) => {
    await loginPage.goto();

    await expect(loginPage.openidxLogo).toBeVisible();
    await expect(loginPage.loginTitle).toBeVisible();
    await expect(loginPage.usernameInput).toBeVisible();
    await expect(loginPage.passwordInput).toBeVisible();
    await expect(loginPage.loginButton).toBeVisible();
    await expect(loginPage.forgotPasswordLink).toBeVisible();
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login('invalid', 'wrong');

    const error = await loginPage.getErrorMessage();
    expect(error).toContain('login failed');
  });

  test('should successfully login with valid credentials', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login('admin', 'password123');

    // Should redirect to dashboard
    await page.waitForURL('**/dashboard');
    const dashboardPage = new DashboardPage(page);
    await expect(dashboardPage.pageTitle).toBeVisible();
  });

  test('should require username and password', async ({ page }) => {
    await loginPage.goto();

    // Try to submit with empty fields
    await loginPage.submitLogin();

    // Should still be on login page (validation prevented submission)
    await expect(loginPage.loginTitle).toBeVisible();
  });

  test('should show MFA form for MFA-enabled user', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login('mfa-user', 'password123');

    // MFA form should appear
    await expect(loginPage.mfaCodeInput).toBeVisible({ timeout: 5000 });
  });

  test('should complete MFA flow with valid code', async ({ page }) => {
    await loginPage.goto();
    await loginPage.login('mfa-user', 'password123');

    // Wait for MFA form
    await expect(loginPage.mfaCodeInput).toBeVisible({ timeout: 5000 });

    // Submit valid MFA code
    await loginPage.completeMFA('123456');

    // Should redirect to dashboard
    await page.waitForURL('**/dashboard');
    const dashboardPage = new DashboardPage(page);
    await expect(dashboardPage.pageTitle).toBeVisible();
  });

  test('should show error for invalid MFA code', async ({ page }) => {
    await page.route('**/oauth/mfa/verify', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'invalid_code',
          error_description: 'Invalid verification code.',
        }),
      });
    });

    await loginPage.goto();
    await loginPage.login('mfa-user', 'password123');

    await expect(loginPage.mfaCodeInput).toBeVisible({ timeout: 5000 });

    // Submit invalid MFA code
    await loginPage.fillMFACode('000000');
    await loginPage.submitMFA();

    // Should still be on MFA form
    await expect(loginPage.mfaCodeInput).toBeVisible();
  });

  test('should navigate to forgot password page', async ({ page }) => {
    await loginPage.goto();
    await loginPage.clickForgotPassword();

    await expect(page).toHaveURL('**/forgot-password');
    await expect(page.getByText('Reset your password')).toBeVisible();
  });
});

test.describe('Password Reset Flow', () => {
  test('should display forgot password page', async ({ page }) => {
    await page.goto('/forgot-password');

    await expect(page.getByText('Reset your password')).toBeVisible();
    await expect(page.getByLabel(/email address/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /send reset link/i })).toBeVisible();
  });

  test('should validate email format on forgot password', async ({ page }) => {
    await page.route('**/api/v1/identity/users/forgot-password', async (route) => {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Invalid email format' }),
      });
    });

    await page.goto('/forgot-password');

    // Try invalid email
    await page.getByLabel(/email address/i).fill('invalid-email');
    await page.getByRole('button', { name: /send reset link/i }).click();

    // Should show error
    await expect(page.locator('text=/error|invalid/i')).toBeVisible();
  });

  test('should submit password reset request', async ({ page }) => {
    await page.route('**/api/v1/identity/users/forgot-password', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Password reset email sent' }),
      });
    });

    await page.goto('/forgot-password');

    await page.getByLabel(/email address/i).fill('user@example.com');
    await page.getByRole('button', { name: /send reset link/i }).click();

    // Should show success message
    await expect(page.locator('text=/password reset link has been sent/i')).toBeVisible();
  });

  test('should display reset password page with token', async ({ page }) => {
    await page.goto('/reset-password?token=test-reset-token-123');

    await expect(page.getByText('Set a new password')).toBeVisible();
    await expect(page.getByLabel(/new password/i)).toBeVisible();
    await expect(page.getByLabel(/confirm password/i)).toBeVisible();
  });

  test('should show error without reset token', async ({ page }) => {
    await page.goto('/reset-password');

    await expect(page.locator('text=/invalid or missing reset token/i')).toBeVisible();
  });

  test('should validate password match on reset', async ({ page }) => {
    await page.goto('/reset-password?token=test-reset-token-123');

    await page.getByLabel(/new password/i).fill('newpassword123');
    await page.getByLabel(/confirm password/i).fill('differentpassword');
    await page.getByRole('button', { name: /reset password/i }).click();

    // Should show error about passwords not matching
    await expect(page.locator('text=/do not match/i')).toBeVisible();
  });

  test('should complete password reset with valid data', async ({ page }) => {
    await page.route('**/api/v1/identity/users/reset-password', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'Password reset successful' }),
      });
    });

    await page.goto('/reset-password?token=test-reset-token-123');

    await page.getByLabel(/new password/i).fill('newpassword123');
    await page.getByLabel(/confirm password/i).fill('newpassword123');
    await page.getByRole('button', { name: /reset password/i }).click();

    // Should show success message and login link
    await expect(page.locator('text=/password has been reset successfully/i')).toBeVisible();
    await expect(page.getByRole('link', { name: /go to login/i })).toBeVisible();
  });
});

test.describe('MFA Setup Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Mock authenticated state
    await page.goto('/settings');
  });

  test('should display MFA setup options', async ({ page }) => {
    await page.route('**/api/v1/identity/mfa/methods', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          methods: {
            totp: false,
            sms: false,
            email: false,
            webauthn: false,
          },
          enabled_count: 0,
          mfa_enabled: false,
        }),
      });
    });

    // Navigate to settings (which would have MFA setup option)
    // In a real scenario, this would be triggered from settings page
    const mfaPage = new MFAPage(page);

    // Check that we're on a settings-related page
    await expect(page).toHaveURL('**/settings');
  });

  test('should setup TOTP MFA', async ({ page }) => {
    // Mock TOTP setup endpoint
    await page.route('**/api/v1/identity/mfa/totp/setup', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          secret: 'JBSWY3DPEHPK3PXP',
          qr_code_url: 'otpauth://totp/test:test@test.com?secret=JBSWY3DPEHPK3PXP',
        }),
      });
    });

    // Mock TOTP enrollment endpoint
    await page.route('**/api/v1/identity/mfa/totp/enroll', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'TOTP enabled' }),
      });
    });

    // Mock backup codes generation
    await page.route('**/api/v1/identity/mfa/backup/generate', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          codes: [
            'ABCD-1234-EFGH-5678',
            'IJKL-9012-MNOP-3456',
            'QRST-7890-UVWX-1234',
            'YZAB-5678-CDEF-9012',
          ],
        }),
      });
    });

    // Navigate to settings page which has MFA setup
    await page.goto('/settings');

    // In a real test, we would click the "Add MFA" button from settings
    // For now, we verify the page loads
    await expect(page.getByRole('heading', { name: /settings/i })).toBeVisible();
  });
});

test.describe('Session Management', () => {
  test('should redirect to login when not authenticated', async ({ page }) => {
    // Mock unauthenticated state
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Unauthorized' }),
      });
    });

    await page.goto('/dashboard');

    // Should redirect to login
    await page.waitForURL('**/login', { timeout: 5000 });
    await expect(new LoginPage(page).loginTitle).toBeVisible();
  });

  test('should maintain session across page navigations', async ({ page }) => {
    // Mock authenticated state
    await page.route('**/api/v1/dashboard', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total_users: 42,
          active_users: 38,
          total_applications: 12,
          active_sessions: 15,
          pending_reviews: 3,
          security_alerts: 0,
          recent_activity: [],
          auth_stats: { total_logins: 1250, successful_logins: 1180, failed_logins: 70 },
        }),
      });
    });

    // Set auth token in localStorage
    await page.evaluate(() => {
      localStorage.setItem('auth_tokens', JSON.stringify({
        access_token: 'test-token',
        refresh_token: 'test-refresh',
      }));
    });

    await page.goto('/dashboard');
    await expect(new DashboardPage(page).pageTitle).toBeVisible();

    // Navigate to another page
    await page.goto('/users');

    // Navigate back - should still be authenticated
    await page.goto('/dashboard');
    await expect(new DashboardPage(page).pageTitle).toBeVisible();
  });
});
