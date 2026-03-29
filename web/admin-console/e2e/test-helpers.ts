import { Page } from '@playwright/test';

/**
 * Mock authentication state for testing
 */
export async function mockAuthentication(page: Page, accessToken = 'test-token', refreshToken = 'test-refresh') {
  await page.evaluate(({ token, refresh }) => {
    localStorage.setItem('auth_tokens', JSON.stringify({
      access_token: token,
      refresh_token: refresh,
    }));
  }, { token: accessToken, refresh: refreshToken });
}

/**
 * Mock user data
 */
export const mockUsers = [
  { id: '1', username: 'admin', email: 'admin@openidx.local', first_name: 'Admin', last_name: 'User', enabled: true, email_verified: true, created_at: '2024-01-01T00:00:00Z' },
  { id: '2', username: 'john.doe', email: 'john@example.com', first_name: 'John', last_name: 'Doe', enabled: true, email_verified: false, created_at: '2024-01-15T00:00:00Z' },
  { id: '3', username: 'jane.smith', email: 'jane@example.com', first_name: 'Jane', last_name: 'Smith', enabled: false, email_verified: true, created_at: '2024-02-01T00:00:00Z' },
];

/**
 * Mock roles data
 */
export const mockRoles = [
  { id: 'role-1', name: 'admin', description: 'Administrator role', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
  { id: 'role-2', name: 'user', description: 'Regular user role', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
  { id: 'role-3', name: 'viewer', description: 'Read-only access', is_composite: false, created_at: '2024-01-01T00:00:00Z' },
];

/**
 * Setup common API mocks for testing
 */
export async function setupCommonAPIMocks(page: Page) {
  // Mock users API
  await page.route('**/api/v1/identity/users*', async (route) => {
    if (route.request().method() === 'GET') {
      const url = new URL(route.request().url());
      const search = url.searchParams.get('search') || '';
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);
      const limit = parseInt(url.searchParams.get('limit') || '20', 10);

      let filteredUsers = mockUsers;
      if (search) {
        filteredUsers = mockUsers.filter(u =>
          u.username.toLowerCase().includes(search.toLowerCase()) ||
          u.email.toLowerCase().includes(search.toLowerCase())
        );
      }

      const paginatedUsers = filteredUsers.slice(offset, offset + limit);

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'x-total-count': String(filteredUsers.length) },
        body: JSON.stringify(paginatedUsers),
      });
    } else if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          id: `user-${Date.now()}`,
          ...body,
          enabled: true,
          email_verified: false,
          created_at: new Date().toISOString(),
        }),
      });
    } else if (route.request().method() === 'DELETE') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ message: 'User deleted' }),
      });
    }
  });

  // Mock roles API
  await page.route('**/api/v1/identity/roles', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(mockRoles),
    });
  });
}

/**
 * Wait for toast notification
 */
export async function waitForToast(page: Page, message?: string, timeout = 5000) {
  const toastSelector = '[role="status"], .toast, [data-testid="toast"]';

  if (message) {
    await page.locator(toastSelector).filter({ hasText: message }).waitFor({ state: 'visible', timeout });
  } else {
    await page.locator(toastSelector).first().waitFor({ state: 'visible', timeout });
  }
}

/**
 * Get all visible toast messages
 */
export async function getToastMessages(page: Page): Promise<string[]> {
  const toastSelector = '[role="status"], .toast, [data-testid="toast"]';
  const toasts = page.locator(toastSelector);
  const count = await toasts.count();
  const messages: string[] = [];

  for (let i = 0; i < count; i++) {
    const text = await toasts.nth(i).textContent();
    if (text) messages.push(text);
  }

  return messages;
}

/**
 * Generate a unique test identifier
 */
export function generateTestId(): string {
  return `test-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

/**
 * Create a test user with unique data
 */
export function createTestUser(prefix = 'test') {
  const id = generateTestId();
  return {
    username: `${prefix}-${id}`,
    email: `${prefix}-${id}@example.com`,
    first_name: 'Test',
    last_name: 'User',
    password: 'TestPassword123!',
  };
}

/**
 * Navigate to page and wait for it to be loaded
 */
export async function navigateAndLoad(page: Page, path: string) {
  await page.goto(path);
  await page.waitForLoadState('networkidle');
}

/**
 * Take screenshot on failure (for use in afterEach hooks)
 */
export async function screenshotOnFailure(page: Page, testName: string) {
  const screenshotPath = `test-results/screenshots/failure-${testName}-${Date.now()}.png`;
  await page.screenshot({ path: screenshotPath, fullPage: true });
}

/**
 * Mock delay for simulating slow API responses
 */
export function createDelayedResponse<T>(data: T, delay: number = 1000): Promise<{ status: number; contentType: string; body: string }> {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(data),
      });
    }, delay);
  });
}

/**
 * Mock error response
 */
export function createErrorResponse(error: string, status: number = 400): { status: number; contentType: string; body: string } {
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify({ error }),
  };
}

/**
 * Setup mock for file upload/download operations
 */
export function setupFileMocks(page: Page) {
  page.route('**/*', async (route) => {
    const url = route.request().url();

    // Handle file download requests
    if (url.includes('/export')) {
      await route.fulfill({
        status: 200,
        contentType: 'text/csv',
        body: 'username,email,first_name,last_name\nadmin,admin@test.com,Admin,User',
      });
      return;
    }

    // Handle file upload requests
    if (url.includes('/import')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          total: 2,
          created: 2,
          errors: 0,
          details: [],
        }),
      });
      return;
    }

    // Continue with other routes
    route.continue();
  });
}

/**
 * Login helper - performs login with mocked auth
 */
export async function login(page: Page, username = 'admin', password = 'password123') {
  // Mock login endpoint
  await page.route('**/oauth/login', async (route) => {
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

  // Navigate to login page
  await page.goto('/login');

  // Fill in credentials
  await page.fill('input[name="username"], input[id="username"]', username);
  await page.fill('input[name="password"], input[type="password"]', password);

  // Submit login
  await page.click('button[type="submit"]');

  // Wait for navigation
  await page.waitForURL('**/dashboard', { timeout: 5000 });
}

/**
 * Setup mock for MFA enrollment
 */
export function setupMFAMocks(page: Page) {
  // Mock MFA methods endpoint
  page.route('**/api/v1/identity/mfa/methods', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        methods: { totp: false, sms: false, email: false, webauthn: false },
        enabled_count: 0,
        mfa_enabled: false,
      }),
    });
  });

  // Mock TOTP setup
  page.route('**/api/v1/identity/mfa/totp/setup', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        secret: 'JBSWY3DPEHPK3PXP',
        qr_code_url: 'otpauth://totp/test:test@test.com?secret=JBSWY3DPEHPK3PXP',
      }),
    });
  });

  // Mock TOTP enrollment
  page.route('**/api/v1/identity/mfa/totp/enroll', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ message: 'TOTP enabled' }),
    });
  });

  // Mock backup codes generation
  page.route('**/api/v1/identity/mfa/backup/generate', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        codes: [
          'ABCD-1234-EFGH-5678',
          'IJKL-9012-MNOP-3456',
          'QRST-7890-UVWX-1234',
        ],
      }),
    });
  });
}
