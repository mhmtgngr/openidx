import { Page, Locator } from '@playwright/test';

/**
 * Base page class with common functionality for all pages
 */
export class BasePage {
  readonly page: Page;
  readonly toastLocator: Locator;
  readonly loadingSpinnerLocator: Locator;

  constructor(page: Page) {
    this.page = page;
    this.toastLocator = page.locator('[role="status"], .toast, [data-testid="toast"]');
    this.loadingSpinnerLocator = page.locator('.loading-spinner, [data-testid="loading"], .animate-spin');
  }

  /**
   * Navigate to a path
   */
  async goto(path: string) {
    await this.page.goto(path);
  }

  /**
   * Wait for page to be loaded (no loading spinners)
   */
  async waitForLoaded() {
    await this.page.waitForLoadState('networkidle');
    // Wait for any loading spinners to disappear
    await this.loadingSpinnerLocator.first().waitFor({ state: 'hidden', timeout: 5000 }).catch(() => {
      // Spinner might not exist, which is fine
    });
  }

  /**
   * Wait for and verify a toast message appears
   */
  async waitForToast(message?: string) {
    if (message) {
      await this.toastLocator.filter({ hasText: message }).waitFor({ state: 'visible' });
    } else {
      await this.toastLocator.first().waitFor({ state: 'visible' });
    }
  }

  /**
   * Check if a toast with specific text is visible
   */
  async isToastVisible(message: string): Promise<boolean> {
    return await this.toastLocator.filter({ hasText: message }).isVisible().catch(() => false);
  }

  /**
   * Get all visible toast messages
   */
  async getToastMessages(): Promise<string[]> {
    const toasts = this.toastLocator.all();
    const messages: string[] = [];
    for (const toast of await toasts) {
      const text = await toast.textContent();
      if (text) messages.push(text);
    }
    return messages;
  }

  /**
   * Click a button by text content
   */
  async clickButton(text: string | RegExp) {
    await this.page.getByRole('button', { name: text }).click();
  }

  /**
   * Fill an input by label
   */
  async fillByLabel(label: string | RegExp, value: string) {
    await this.page.getByLabel(label).fill(value);
  }

  /**
   * Wait for URL to contain a path
   */
  async waitForUrl(path: string) {
    await this.page.waitForURL(`**${path}**`);
  }
}
