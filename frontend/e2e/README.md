# OpenIDX E2E Tests

End-to-end tests for the OpenIDX Admin Console using Playwright.

## Setup

Install dependencies:
```bash
npm install
```

Install Playwright browsers:
```bash
npx playwright install
```

## Running Tests

Run all tests:
```bash
npm run test:e2e
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

Example:
```bash
PLAYWRIGHT_BASE_URL=https://openidx.tdv.org \
TEST_ADMIN_USERNAME=admin \
TEST_ADMIN_PASSWORD=admin123 \
npm run test:e2e
```

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
