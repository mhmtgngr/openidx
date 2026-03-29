import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright E2E Test Configuration for Frontend
 *
 * This config runs tests against the admin console at http://localhost:5173
 * The dev server is automatically started before tests run.
 */

export default defineConfig({
  testDir: './',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Use single worker to avoid resource contention
  timeout: 60000, // Increase test timeout to 60 seconds
  reporter: [
    ['html', { outputFolder: '../../web/admin-console/playwright-report-frontend' }],
    ['list'],
  ],

  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    actionTimeout: 15000, // Increase action timeout
    navigationTimeout: 30000, // Increase navigation timeout
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],

  // Start the dev server before running tests
  webServer: {
    command: 'cd ../../web/admin-console && npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
})
