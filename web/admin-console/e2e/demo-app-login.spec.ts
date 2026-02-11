import { test, expect } from '@playwright/test';

// Test the demo app login flow via APISIX forward-auth
test.use({ storageState: { cookies: [], origins: [] }, ignoreHTTPSErrors: true });

test('demo app login via forward-auth shows identity', async ({ page }) => {
  // Enable console log capture for debugging
  page.on('console', msg => console.log('BROWSER:', msg.text()));

  // Pre-check: verify the APISIX route for demo.localtest.me is active
  console.log('Pre-check: Testing if demo.localtest.me route is available...');
  const checkResp = await page.request.get('http://localhost:8088/', {
    headers: { 'Host': 'demo.localtest.me' },
    maxRedirects: 0,
    failOnStatusCode: false,
  });
  const checkBody = await checkResp.text();
  if (checkBody.includes('no route configured for host')) {
    test.skip(true, 'APISIX route for demo.localtest.me is not loaded — restart APISIX or reseed config');
    return;
  }
  console.log(`  Route check: status=${checkResp.status()}`);

  // Navigate to demo app via APISIX - should redirect to OAuth login
  console.log('Step 1: Navigate to demo app...');
  await page.goto('http://demo.localtest.me:8088/', { waitUntil: 'domcontentloaded', timeout: 30000 });
  console.log('Step 1 done. URL:', page.url());
  await page.screenshot({ path: 'test-results/demo-step1.png' });

  // Wait for the login form to appear (could be on OAuth page or inline)
  console.log('Step 2: Wait for login form...');
  await page.waitForSelector('input[name="username"], input[type="text"], #username', { timeout: 15000 });
  console.log('Step 2 done. URL:', page.url());
  await page.screenshot({ path: 'test-results/demo-step2.png' });

  // Fill in credentials
  console.log('Step 3: Fill credentials...');
  const usernameField = page.locator('input[name="username"], input[type="text"], #username').first();
  const passwordField = page.locator('input[name="password"], input[type="password"], #password').first();
  await usernameField.fill('admin');
  await passwordField.fill('Admin@123');
  await page.screenshot({ path: 'test-results/demo-step3.png' });

  // Submit the form
  console.log('Step 4: Submit...');
  await page.click('button[type="submit"]');

  // Wait a bit for redirect
  await page.waitForTimeout(5000);
  console.log('Step 4 done. URL:', page.url());
  await page.screenshot({ path: 'test-results/demo-step4.png' });

  // Check final URL and content
  const finalURL = page.url();
  console.log('Final URL:', finalURL);
  const bodyText = await page.textContent('body');
  console.log('Body text (first 500):', bodyText?.substring(0, 500));

  // The test passes if we end up on the demo app with identity shown
  if (finalURL.includes('demo.localtest.me')) {
    await expect(page.locator('body')).toContainText('Authenticated');
  } else {
    // Log the page for debugging
    console.log('Did not reach demo app. Final URL:', finalURL);
    expect(finalURL).toContain('demo.localtest.me');
  }
});
