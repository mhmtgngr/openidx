# OpenIDX E2E Tests

End-to-end tests for the OpenIDX Admin Console using Playwright.

## Setup

The suite drives a **real stack**: the eight services plus a database, not
mocks. Start one first — `make dev` locally, or see the `e2e` job in
`.github/workflows/ci.yml`, which is this suite's reference environment.

Install dependencies and a browser:
```bash
npm install
npx playwright install --with-deps chromium
```

With no `PLAYWRIGHT_BASE_URL` set, Playwright starts `npm run dev` itself on
**:3000** and points the suite at it. That port is not arbitrary: the seeded
`admin-console` OAuth client registers `http://localhost:3000/login`, and Vite's
proxy routes each API prefix to its own service. On any other port the sign-in
round trip ends at "redirect_uri not registered for client".

## What CI runs, and what it does not

`suite.txt` is the register: one line per spec file, `run` or
`hold <reason>`. The `e2e` job in CI runs the `run` lines only.

The suite was written against a mocked console and did not execute until it was
wired into CI. Measured against a real stack it is **448 passed, 282 failed**:
some specs drive an external host, some need fixture users, passkeys, devices
or a Ziti controller nothing seeds, and some assert copy and DOM shapes the
console no longer has. Those files are held — not deleted, not `test.skip`'d,
still run by `npm run test:e2e` — each with the reason on its line.

`scripts/check-e2e-suite.sh` (enforced in the `UI safety guards` job) fails if
a spec file is missing from the register, if a `hold` carries no reason, or if
a listed file has been renamed away, so nothing leaves the gate silently.
Moving a file from `hold` to `run` is how coverage grows.

## Running Tests

Run all tests, held ones included:
```bash
npm run test:e2e
```

Run exactly what CI runs:
```bash
npx playwright test --project=chromium $(awk '$1 == "run" { print $2 }' e2e/suite.txt)
```

Run tests in headed mode (see browser):
```bash
npm run test:e2e:headed
```

Run tests with UI:
```bash
npm run test:e2e:ui
```

View test report:
```bash
npm run test:e2e:report
```

## Test Structure

- `landing.spec.ts` - Tests for the public landing page
- `login.noauth.spec.ts` - Authentication flow tests (no auth required)
- `dashboard.spec.ts` - Dashboard and authenticated pages
- `mfa.spec.ts` - Multi-factor authentication tests
- `api.spec.ts` - API integration and error handling
- `production.spec.ts` - Production environment specific tests

## Environment Variables

- `PLAYWRIGHT_BASE_URL` - Base URL for tests (default: http://localhost:3000)
- `TEST_ADMIN_USERNAME` - Admin username for auth tests
- `TEST_ADMIN_PASSWORD` - Admin password for auth tests

`TEST_ADMIN_PASSWORD` defaults to `Admin@123`, the seeded admin's password.
Set both when pointing at a deployment where it has been changed — which every
production deployment must have done, since the first-run gate does not release
the console until it is.

Example:
```bash
PLAYWRIGHT_BASE_URL=https://openidx.example.org \
TEST_ADMIN_USERNAME=admin \
TEST_ADMIN_PASSWORD='<the admin password>' \
npm run test:e2e
```

## Authentication

`auth.setup.ts` signs in once as a `setup` project that every browser project
depends on, and saves the session to `e2e/.auth/user.json`; specs start
authenticated. A spec that wants a signed-out browser opts out explicitly:

```typescript
test.use({ storageState: { cookies: [], origins: [] } })
```

The sign-in it drives is the product's real one: `/login` shows a single
"Sign in with OpenIDX" button, which hands off to `/oauth/authorize`, which
mints a `login_session` and redirects back to `/login` — and only then does the
credential form render.

## Writing New Tests

1. Create a new spec file or add to an existing one
2. Use descriptive test names
3. Follow the existing patterns for assertions
4. Add tests for both positive and negative cases

```typescript
import { test, expect } from '@playwright/test'

test.describe('My Feature', () => {
  test('should do something', async ({ page }) => {
    await page.goto('/my-page')
    await expect(page.locator('h1')).toContainText('My Page')
  })
})
```

## CI/CD Integration

Tests can be run in CI/CD with:

```bash
# Install browsers in CI
npx playwright install --with-deps

# Run tests
npm run test:e2e

# Upload report
npx playwright merge-reports
```
