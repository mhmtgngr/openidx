import { test as setup, expect } from '@playwright/test'

const authFile = 'e2e/.auth/user.json'

// Signs in once and saves the storage state every authenticated spec starts
// from (playwright.config.ts wires this as the `setup` project each browser
// depends on).
//
// The flow this drives is the one the product actually has, not the one this
// file used to assume. /login opens on a single "Sign in with OpenIDX" button:
// the console IS the login UI, so it sends the browser to
// /oauth/authorize, which mints a login_session and redirects back to
// /login?login_session=… — and only then does the username/password form
// render. The previous version waited 5s for input#username on the first page
// and gave up. (It also defaulted to the password `admin123`, which matches
// nothing; the seeded admin is `Admin@123`.)
setup('authenticate as admin', async ({ page, context }) => {
  const username = process.env.TEST_ADMIN_USERNAME || 'admin'
  const password = process.env.TEST_ADMIN_PASSWORD || 'Admin@123'

  await page.goto('/login')

  // Step 1: hand off to the authorization endpoint. Already carrying a
  // login_session (a retry, or a deployment that lands here directly) means
  // the form is on screen and there is nothing to click.
  const form = page.locator('input#username')
  if ((await form.count()) === 0) {
    await page.getByRole('button', { name: /sign in with openidx/i }).click()
  }

  // Step 2: the credential form, after the redirect back.
  await page.waitForSelector('input#username', { timeout: 20000 })
  await page.fill('input#username', username)
  await page.fill('input#password', password)
  await page.click('button[type="submit"]')

  // Step 3: the code comes back to /login, is exchanged for a token, and the
  // app routes to the dashboard.
  await page.waitForURL(/\/dashboard/, { timeout: 30000 })
  await expect(page.locator('h1')).toBeVisible()

  await context.storageState({ path: authFile })
})
