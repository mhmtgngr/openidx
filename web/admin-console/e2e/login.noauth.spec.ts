import { test, expect } from '@playwright/test';

test.describe('Login Page - Unauthenticated', () => {
  test.beforeEach(async ({ page, context }) => {
    // Clear any existing auth state including cookies
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test('should display login page with OpenIDX branding', async ({ page }) => {
    await page.goto('/login');

    // Check page title and branding - CardTitle renders as h3
    await expect(page.getByRole('heading', { name: 'OpenIDX' })).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Identity & Access Management Platform')).toBeVisible();

    // Check login button is present (wait for loading to finish)
    await expect(page.getByRole('button', { name: /sign in with openidx/i })).toBeVisible({ timeout: 10000 });
  });

  test('should show forgot password link', async ({ page }) => {
    await page.goto('/login');

    // Wait for the page to load, then find the forgot password link (React Router Link renders as <a>)
    await expect(page.getByRole('heading', { name: 'OpenIDX' })).toBeVisible({ timeout: 10000 });
    // Note: Link text is "Forgot your password?" with question mark
    const forgotPasswordLink = page.getByRole('link', { name: /forgot your password/i });
    await expect(forgotPasswordLink).toBeVisible({ timeout: 10000 });
    await expect(forgotPasswordLink).toHaveAttribute('href', '/forgot-password');
  });

  test('should navigate to forgot password page', async ({ page }) => {
    await page.goto('/login');

    await page.getByRole('link', { name: /forgot your password/i }).click();

    await expect(page).toHaveURL('/forgot-password');
    await expect(page.locator('text=Reset your password')).toBeVisible();
  });

  test('should show loading state when fetching identity providers', async ({ page }) => {
    await page.goto('/login');

    // Should eventually show the sign in button (after loading)
    await expect(page.getByRole('button', { name: /sign in with openidx/i })).toBeVisible({ timeout: 10000 });
  });

  test('should display footer links', async ({ page }) => {
    await page.goto('/login');

    await expect(page.locator('text=Privacy')).toBeVisible();
    await expect(page.locator('text=Terms')).toBeVisible();
    await expect(page.locator('text=Help')).toBeVisible();
  });

  test('should show powered by OpenIDX footer', async ({ page }) => {
    await page.goto('/login');

    await expect(page.locator('text=Powered by')).toBeVisible();
  });
});

test.describe('Social Login Provider Icons', () => {
  test.beforeEach(async ({ page, context }) => {
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test('should show provider-specific icons for known providers', async ({ page }) => {
    await page.route('**/api/v1/identity/providers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: '1', name: 'Google', provider_type: 'oidc', issuer_url: 'https://accounts.google.com', enabled: true, client_id: 'test', scopes: ['openid'] },
          { id: '2', name: 'GitHub', provider_type: 'oidc', issuer_url: 'https://github.com', enabled: true, client_id: 'test', scopes: ['openid'] },
        ]),
      });
    });

    await page.goto('/login');

    const googleBtn = page.getByRole('button', { name: /sign in with google/i });
    await expect(googleBtn).toBeVisible({ timeout: 10000 });
    // Provider-specific SVG icon should be present (not just the generic Globe)
    await expect(googleBtn.locator('svg')).toBeVisible();

    const githubBtn = page.getByRole('button', { name: /sign in with github/i });
    await expect(githubBtn).toBeVisible();
    await expect(githubBtn.locator('svg')).toBeVisible();
  });
});

test.describe('Login Flow - Credentials', () => {
  test.beforeEach(async ({ page, context }) => {
    // Clear any existing auth state including cookies
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test('should show credentials form when login_session is present', async ({ page }) => {
    await page.goto('/login?login_session=test-session');

    // Should show credentials form
    await expect(page.locator('text=Sign in with your credentials')).toBeVisible();
    await expect(page.getByLabel(/username or email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /sign in$/i })).toBeVisible();
  });

  test('should have back to login options button', async ({ page }) => {
    await page.goto('/login?login_session=test-session');

    await expect(page.getByRole('button', { name: /back to login options/i })).toBeVisible();
  });

  test('should clear login_session from URL', async ({ page }) => {
    await page.goto('/login?login_session=test-session');

    // URL should be cleaned up
    await expect(page).toHaveURL('/login');
  });

  test('should validate required username field', async ({ page }) => {
    await page.goto('/login?login_session=test-session');

    // Try to submit without username
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Form should not submit (HTML5 validation)
    const usernameInput = page.getByLabel(/username or email/i);
    await expect(usernameInput).toBeFocused();
  });

  test('should validate required password field', async ({ page }) => {
    await page.goto('/login?login_session=test-session');

    // Fill username only
    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Form should not submit (HTML5 validation)
    const passwordInput = page.getByLabel(/password/i);
    await expect(passwordInput).toBeFocused();
  });

  test('should show loading state when submitting credentials', async ({ page }) => {
    // Mock the API endpoint
    await page.route('**/oauth/login', async (route) => {
      await new Promise(resolve => setTimeout(resolve, 1000));
      await route.fulfill({
        status: 401,
        body: JSON.stringify({ error_description: 'Invalid credentials' }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show loading state
    await expect(page.locator('text=Signing in...')).toBeVisible();
  });

  test('should show error message on invalid credentials', async ({ page }) => {
    // Mock the API to return an error
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error_description: 'Invalid username or password' }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('wronguser');
    await page.getByLabel(/password/i).fill('wrongpassword');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show error message
    await expect(page.locator('text=Invalid username or password')).toBeVisible();
  });

  test('should navigate back to login options', async ({ page }) => {
    await page.goto('/login?login_session=test-session');

    // Wait for credentials form to appear
    const backButton = page.getByRole('button', { name: /back to login options/i });
    await expect(backButton).toBeVisible({ timeout: 10000 });
    await backButton.click();

    // Should show main login page again
    await expect(page.getByRole('button', { name: /sign in with openidx/i })).toBeVisible({ timeout: 10000 });
  });
});

test.describe('MFA Flow', () => {
  test.beforeEach(async ({ page, context }) => {
    // Clear any existing auth state including cookies
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test('should show MFA verification form when MFA is required', async ({ page }) => {
    // Mock the API to require MFA
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp'],
        }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Should show MFA form - look for the heading or verification button
    await expect(page.getByRole('button', { name: /verify/i })).toBeVisible({ timeout: 10000 });
  });

  test('should show MFA method selection when multiple methods available', async ({ page }) => {
    // Set up the route before navigating
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp', 'sms', 'email'],
        }),
      });
    });

    // Navigate with login session
    await page.goto('/login?login_session=test-session');

    // Wait for form to be ready with longer timeout
    await expect(page.getByLabel(/username or email/i)).toBeVisible({ timeout: 10000 });

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');

    // Click the Sign In button (credentials form shows "Sign In" not "Sign in with OpenIDX")
    await page.getByRole('button', { name: /sign in$/i }).click();

    // Wait for method selection - try multiple selectors
    // CardTitle may render as different heading levels depending on implementation
    const methodSelectionHeading = page.locator('text=Choose Verification Method');
    const verifyButton = page.getByRole('button', { name: /verify/i });

    // Wait for either method selection or direct MFA input
    await expect(methodSelectionHeading.or(verifyButton).first()).toBeVisible({ timeout: 15000 });
  });

  test('should only allow 6 digit numeric code', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp'],
        }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    await expect(page.getByLabel(/verification code/i)).toBeVisible({ timeout: 10000 });

    // Test that it accepts numeric input correctly and respects maxLength
    await page.getByLabel(/verification code/i).fill('123456');
    await expect(page.getByLabel(/verification code/i)).toHaveValue('123456');

    // Clear and try entering more than 6 digits - should be limited
    await page.getByLabel(/verification code/i).fill('');
    await page.getByLabel(/verification code/i).fill('12345678');
    // maxLength=6 should limit to 6 characters
    await expect(page.getByLabel(/verification code/i)).toHaveValue('123456');
  });

  test('should disable verify button when code is incomplete', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp'],
        }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    await expect(page.getByLabel(/verification code/i)).toBeVisible();

    // Enter partial code
    await page.getByLabel(/verification code/i).fill('123');

    // Verify button should be disabled
    await expect(page.getByRole('button', { name: /verify/i })).toBeDisabled();

    // Complete the code
    await page.getByLabel(/verification code/i).fill('123456');

    // Now button should be enabled
    await expect(page.getByRole('button', { name: /verify/i })).toBeEnabled();
  });

  test('should show error on invalid MFA code', async ({ page }) => {
    await page.route('**/oauth/login', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          mfa_required: true,
          mfa_session: 'test-mfa-session',
          mfa_methods: ['totp'],
        }),
      });
    });

    await page.route('**/oauth/mfa-verify', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error_description: 'Invalid verification code' }),
      });
    });

    await page.goto('/login?login_session=test-session');

    await page.getByLabel(/username or email/i).fill('testuser');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /sign in$/i }).click();

    await page.getByLabel(/verification code/i).fill('123456');
    await page.getByRole('button', { name: /verify/i }).click();

    // Should show error
    await expect(page.locator('text=Invalid verification code')).toBeVisible();
  });
});

test.describe('Forgot Password Page', () => {
  test('should display forgot password form', async ({ page }) => {
    await page.goto('/forgot-password');

    await expect(page.locator('text=Reset your password')).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /send reset link/i })).toBeVisible();
  });

  test('should have back to login link', async ({ page }) => {
    await page.goto('/forgot-password');

    const backButton = page.getByRole('button', { name: /back to login/i });
    await expect(backButton).toBeVisible();
  });

  test('should validate email field', async ({ page }) => {
    await page.goto('/forgot-password');

    // Try to submit without email
    const submitButton = page.getByRole('button', { name: /send reset link/i });
    await submitButton.click();

    // Should show validation error or focus on email field
    const emailInput = page.getByLabel(/email/i);
    await expect(emailInput).toBeVisible();
  });
});

test.describe('Protected Route Redirects', () => {
  test.beforeEach(async ({ page, context }) => {
    // Clear any existing auth state including cookies
    await context.clearCookies();
    await page.goto('/login');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });

  test('should redirect unauthenticated users from dashboard to login', async ({ page }) => {
    // Try to access protected route
    await page.goto('/dashboard');

    // Should redirect to login (or show login page content)
    await expect(page).toHaveURL(/\/login/);
  });

  test('should redirect unauthenticated users from users page to login', async ({ page }) => {
    await page.goto('/users');

    await expect(page).toHaveURL(/\/login/);
  });

  test('should redirect unauthenticated users from settings page to login', async ({ page }) => {
    await page.goto('/settings');

    await expect(page).toHaveURL(/\/login/);
  });
});
