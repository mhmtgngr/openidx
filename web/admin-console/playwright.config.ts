import { defineConfig, devices } from '@playwright/test'

// Where the console is served. The README has documented PLAYWRIGHT_BASE_URL
// since the suite was written; the config ignored it and hardcoded :5173, so
// the documented way to point the suite at a deployment did nothing.
const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:3000'

// Storage state written by e2e/auth.setup.ts.
const authFile = 'e2e/.auth/user.json'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  // Measured: 418 tests in 11.6 minutes at 4 workers against a real stack, and
  // green -- the specs that mutate shared state (users CRUD, Ziti services)
  // scope their fixtures well enough to run alongside each other. One worker
  // would put the CI job near 40 minutes.
  workers: process.env.CI ? 4 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'html',
  use: {
    baseURL,
    trace: 'on-first-retry',
  },

  projects: [
    // The suite's authenticated specs assume a signed-in storageState, and the
    // specs that do NOT want one opt out explicitly with
    // `test.use({ storageState: { cookies: [], origins: [] } })`. That only
    // makes sense if the default IS authenticated -- and it was not: no project
    // declared a dependency on auth.setup.ts, and .setup.ts does not match
    // Playwright's default testMatch, so the setup never ran and no
    // storageState was ever written. Every "authenticated" spec was running
    // signed out.
    {
      name: 'setup',
      testMatch: /.*\.setup\.ts/,
    },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], storageState: authFile },
      dependencies: ['setup'],
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'], storageState: authFile },
      dependencies: ['setup'],
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'], storageState: authFile },
      dependencies: ['setup'],
    },
  ],

  // Only start a dev server when pointing at the default local one. With
  // PLAYWRIGHT_BASE_URL set (an operator pointing at a deployment) there is
  // nothing to start, and Playwright would sit waiting on a port nothing is
  // going to bind.
  webServer: process.env.PLAYWRIGHT_BASE_URL
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://localhost:3000',
        reuseExistingServer: !process.env.CI,
      },
})
