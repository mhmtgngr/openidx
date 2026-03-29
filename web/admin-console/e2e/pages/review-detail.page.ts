import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Page Object Model for the Review Detail page
 */
export class ReviewDetailPage extends BasePage {
  readonly path: string;
  readonly backButton: Locator;
  readonly reviewTitle: Locator;
  readonly startReviewButton: Locator;
  readonly completeReviewButton: Locator;
  readonly reviewItemsTable: Locator;
  readonly itemRows: Locator;
  readonly selectAllCheckbox: Locator;
  readonly approveButton: Locator;
  readonly revokeButton: Locator;
  readonly flagButton: Locator;
  readonly decisionModalTitle: Locator;
  readonly commentsTextarea: Locator;
  readonly confirmDecisionButton: Locator;
  readonly pendingItemsCount: Locator;
  readonly progressCard: Locator;
  readonly filterSelect: Locator;

  constructor(page: Page, reviewId: string) {
    super(page);
    this.path = `/access-reviews/${reviewId}`;
    this.backButton = page.getByRole('button', { name: '' }).locator('svg').first();
    this.reviewTitle = page.locator('h1');
    this.startReviewButton = page.getByRole('button', { name: /start review/i });
    this.completeReviewButton = page.getByRole('button', { name: /complete review/i });
    this.reviewItemsTable = page.locator('table').filter({ has: page.locator('thead') });
    this.itemRows = page.locator('tr').filter({ has: page.locator('td') });
    this.selectAllCheckbox = page.locator('thead input[type="checkbox"]');
    this.approveButton = page.getByRole('button', { name: /approve selected/i });
    this.revokeButton = page.getByRole('button', { name: /revoke selected/i });
    this.flagButton = page.getByRole('button', { name: /flag selected/i });
    this.decisionModalTitle = page.getByRole('heading', { name: /(approve|revoke|flag)/i });
    this.commentsTextarea = page.locator('textarea[name="comments"], textarea[id="comments"]');
    this.confirmDecisionButton = page.getByRole('button', { name: /(approve|revoke|flag) \d+ items/i });
    this.pendingItemsCount = page.locator('.grid > div').filter({ hasText: /pending items/i }).locator('.text-2xl');
    this.progressCard = page.locator('.grid > div').filter({ hasText: /progress/i });
    this.filterSelect = page.locator('select');
  }

  /**
   * Navigate to the review detail page
   */
  async goto() {
    await this.page.goto(this.path);
    await this.waitForLoaded();
  }

  /**
   * Start the review (if status is pending)
   */
  async startReview() {
    await this.startReviewButton.click();
    await this.waitForLoaded();
  }

  /**
   * Complete the review (if all items are reviewed)
   */
  async completeReview() {
    await this.completeReviewButton.click();
    await this.waitForLoaded();
  }

  /**
   * Get count of review items
   */
  async getItemCount(): Promise<number> {
    return await this.itemRows.count();
  }

  /**
   * Select all pending items
   */
  async selectAllItems() {
    await this.selectAllCheckbox.click();
  }

  /**
   * Select a specific item by index
   */
  async selectItem(index: number) {
    const checkboxes = this.itemRows.locator('input[type="checkbox"]');
    await checkboxes.nth(index).check();
  }

  /**
   * Approve selected items
   */
  async approveSelected(comments?: string) {
    await this.approveButton.click();
    await this.decisionModalTitle.waitFor({ state: 'visible' });
    if (comments) {
      await this.commentsTextarea.fill(comments);
    }
    await this.confirmDecisionButton.click();
    await this.decisionModalTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Revoke selected items
   */
  async revokeSelected(comments?: string) {
    await this.revokeButton.click();
    await this.decisionModalTitle.waitFor({ state: 'visible' });
    if (comments) {
      await this.commentsTextarea.fill(comments);
    }
    await this.confirmDecisionButton.click();
    await this.decisionModalTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Flag selected items
   */
  async flagSelected(comments?: string) {
    await this.flagButton.click();
    await this.decisionModalTitle.waitFor({ state: 'visible' });
    if (comments) {
      await this.commentsTextarea.fill(comments);
    }
    await this.confirmDecisionButton.click();
    await this.decisionModalTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Quick approve a single item by clicking the approve button in its row
   */
  async quickApproveItem(rowIndex: number) {
    const row = this.itemRows.nth(rowIndex);
    const approveBtn = row.getByRole('button').filter({ hasText: /approve/i });
    await approveBtn.click();
  }

  /**
   * Quick revoke a single item by clicking the revoke button in its row
   */
  async quickRevokeItem(rowIndex: number) {
    const row = this.itemRows.nth(rowIndex);
    const revokeBtn = row.getByRole('button').filter({ hasText: /revoke/i });
    await revokeBtn.click();
  }

  /**
   * Quick flag a single item by clicking the flag button in its row
   */
  async quickFlagItem(rowIndex: number) {
    const row = this.itemRows.nth(rowIndex);
    const flagBtn = row.getByRole('button').filter({ hasText: /flag/i });
    await flagBtn.click();
  }

  /**
   * Get item decision status
   */
  async getItemDecision(rowIndex: number): Promise<string | null> {
    const row = this.itemRows.nth(rowIndex);
    const decisionBadge = row.locator('[class*="badge"], [class*="Badge"], span[class*="rounded-full"]');
    if (await decisionBadge.isVisible().catch(() => false)) {
      return await decisionBadge.textContent();
    }
    return null;
  }

  /**
   * Filter items by decision status
   */
  async filterByDecision(status: '' | 'pending' | 'approved' | 'revoked' | 'flagged') {
    await this.filterSelect.selectOption(status);
    await this.waitForLoaded();
  }

  /**
   * Get pending items count
   */
  async getPendingItemsCount(): Promise<number> {
    const text = await this.pendingItemsCount.textContent();
    return parseInt(text?.replace(/,/g, '') || '0', 10);
  }

  /**
   * Get progress percentage
   */
  async getProgressPercentage(): Promise<number> {
    const text = await this.progressCard.locator('.text-2xl').textContent();
    const match = text?.match(/(\d+)\/(\d+)/);
    if (match) {
      const reviewed = parseInt(match[1], 10);
      const total = parseInt(match[2], 10);
      return total > 0 ? Math.round((reviewed / total) * 100) : 0;
    }
    return 0;
  }

  /**
   * Go back to reviews list
   */
  async goBack() {
    await this.backButton.click();
  }
}
