import { test as setup, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const authFile = path.join(__dirname, '.auth/user.json');

/**
 * Authentication setup for Playwright tests
 * This creates a reusable authenticated state that other tests can use
 */
setup('authenticate', async ({ page, context }) => {
  // For testing, we'll mock the authentication by setting localStorage directly
  // First, navigate to any page to initialize the context
  await page.goto('/login');

  // Wait for page to be ready (with generous timeout for dev server startup)
  await page.waitForLoadState('networkidle', { timeout: 30000 }).catch(() => {
    // If networkidle fails, just continue - the page might be ready enough
  });

  // Create a mock JWT token for testing (expires in 1 hour)
  const mockPayload = {
    sub: 'test-user-id',
    email: 'admin@openidx.local',
    name: 'Test Admin',
    preferred_username: 'admin',
    roles: ['admin', 'user'],
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    iat: Math.floor(Date.now() / 1000),
  };

  // Base64 encode the payload (simplified JWT for testing)
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify(mockPayload));
  const mockToken = `${header}.${payload}.mock-signature`;

  // Set the token in localStorage before navigating
  await context.addInitScript((token) => {
    localStorage.setItem('token', token);
    localStorage.setItem('refresh_token', 'mock-refresh-token');
  }, mockToken);

  // Navigate to dashboard to verify auth works
  await page.goto('/dashboard');

  // Wait for navigation to complete
  await page.waitForLoadState('domcontentloaded', { timeout: 10000 }).catch(() => {});

  // Save the storage state
  await page.context().storageState({ path: authFile });
});
