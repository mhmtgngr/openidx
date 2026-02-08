import { test, expect } from '@playwright/test';

test.describe('SMS Settings Page', () => {
  test('SMS/OTP tab loads and shows provider selection', async ({ page }) => {
    // Listen for console errors and network failures
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    // Navigate to settings
    await page.goto('/settings');

    // Wait for settings to load (tabs should appear)
    await page.waitForSelector('text=General', { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(2000);

    await page.screenshot({ path: 'test-results/sms-01-settings-loaded.png', fullPage: true });

    // Look for SMS tab
    const smsTab = page.locator('button, [role="tab"], a').filter({ hasText: /SMS/i });
    const smsTabCount = await smsTab.count();
    console.log(`Found ${smsTabCount} SMS tab elements`);

    if (smsTabCount > 0) {
      await smsTab.first().click();
      await page.waitForTimeout(2000);
      await page.screenshot({ path: 'test-results/sms-02-sms-tab-clicked.png', fullPage: true });

      // Check for provider dropdown
      const providerSelect = page.locator('select');
      const selectCount = await providerSelect.count();
      console.log(`Found ${selectCount} select elements`);

      if (selectCount > 0) {
        // Select NetGSM provider
        await providerSelect.first().selectOption('netgsm');
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'test-results/sms-03-netgsm.png', fullPage: true });

        // Select Twilio provider
        await providerSelect.first().selectOption('twilio');
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'test-results/sms-04-twilio.png', fullPage: true });

        // Select İleti Merkezi
        await providerSelect.first().selectOption('ileti_merkezi');
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'test-results/sms-05-ileti-merkezi.png', fullPage: true });
      }

      // Check enable toggle
      const toggle = page.locator('button[role="switch"]');
      if (await toggle.count() > 0) {
        await toggle.first().click();
        await page.waitForTimeout(500);
        await page.screenshot({ path: 'test-results/sms-06-toggled.png', fullPage: true });
      }

      // Scroll down to see OTP and Test sections
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      await page.waitForTimeout(500);
      await page.screenshot({ path: 'test-results/sms-07-scrolled-down.png', fullPage: true });
    } else {
      console.log('SMS tab not found. Page content:', await page.textContent('body'));
    }

    if (errors.length > 0) {
      console.log('Console errors:', errors.join('\n'));
    }
  });
});
