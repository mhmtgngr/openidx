import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Page Object Model for the Access Reviews page
 */
export class AccessReviewsPage extends BasePage {
  readonly path = '/access-reviews';
  readonly pageTitle: Locator;
  readonly pageDescription: Locator;
  readonly createReviewButton: Locator;
  readonly searchInput: Locator;
  readonly statusFilter: Locator;
  readonly reviewsTable: Locator;
  readonly reviewRows: Locator;
  readonly noReviewsMessage: Locator;
  readonly createReviewDialogTitle: Locator;
  readonly reviewNameInput: Locator;
  readonly reviewDescriptionInput: Locator;
  readonly reviewTypeSelect: Locator;
  readonly startDateInput: Locator;
  readonly endDateInput: Locator;
  readonly createReviewSubmitButton: Locator;
  readonly cancelButton: Locator;
  readonly pendingCount: Locator;
  readonly inProgressCount: Locator;
  readonly completedCount: Locator;

  constructor(page: Page) {
    super(page);
    this.pageTitle = page.getByRole('heading', { name: 'Access Reviews', exact: true });
    this.pageDescription = page.locator('text=Manage access certifications and reviews');
    this.createReviewButton = page.getByRole('button', { name: /create review/i });
    this.searchInput = page.getByPlaceholder(/search reviews/i);
    this.statusFilter = page.locator('button, select').filter({ hasText: /all statuses|pending|in progress|completed/i });
    this.reviewsTable = page.locator('table').filter({ has: page.locator('thead') });
    this.reviewRows = page.locator('tr').filter({ has: page.locator('td') });
    this.noReviewsMessage = page.locator('text=/no access reviews found/i');
    this.createReviewDialogTitle = page.getByRole('heading', { name: /create access review/i });
    this.reviewNameInput = page.locator('input[name="name"], input[id="name"]');
    this.reviewDescriptionInput = page.locator('textarea[name="description"], textarea[id="description"]');
    this.reviewTypeSelect = page.locator('button, select').filter({ hasText: /select review type|user access review/i });
    this.startDateInput = page.locator('input[name="start_date"], input[id="start_date"]');
    this.endDateInput = page.locator('input[name="end_date"], input[id="end_date"]');
    this.createReviewSubmitButton = page.getByRole('button', { name: /create review/i });
    this.cancelButton = page.getByRole('button', { name: /^cancel$/i });
    this.pendingCount = page.locator('.grid > div').filter({ hasText: /pending/ }).locator('.text-2xl');
    this.inProgressCount = page.locator('.grid > div').filter({ hasText: /in progress/i }).locator('.text-2xl');
    this.completedCount = page.locator('.grid > div').filter({ hasText: /completed/i }).locator('.text-2xl');
  }

  /**
   * Navigate to the access reviews page
   */
  async goto() {
    await this.page.goto(this.path);
    await this.waitForLoaded();
    await this.pageTitle.waitFor({ state: 'visible' });
  }

  /**
   * Search for reviews by keyword
   */
  async search(query: string) {
    await this.searchInput.fill(query);
    await this.page.waitForTimeout(300);
  }

  /**
   * Filter reviews by status
   */
  async filterByStatus(status: 'pending' | 'in_progress' | 'completed' | 'expired' | 'all') {
    await this.statusFilter.click();
    const statusOption = this.page.getByRole('option', { name: new RegExp(status, 'i') });
    if (await statusOption.isVisible()) {
      await statusOption.click();
    }
    await this.page.waitForTimeout(300);
  }

  /**
   * Click Create Review button to open the modal
   */
  async openCreateReviewModal() {
    await this.createReviewButton.click();
    await this.createReviewDialogTitle.waitFor({ state: 'visible' });
  }

  /**
   * Fill in the create review form
   */
  async fillReviewForm(data: {
    name: string;
    description?: string;
    type?: string;
    startDate?: string;
    endDate?: string;
  }) {
    await this.reviewNameInput.fill(data.name);
    if (data.description !== undefined) {
      await this.reviewDescriptionInput.fill(data.description);
    }
    if (data.type !== undefined) {
      await this.reviewTypeSelect.click();
      const typeOption = this.page.getByRole('option', { name: new RegExp(data.type, 'i') });
      if (await typeOption.isVisible()) {
        await typeOption.click();
      }
    }
    if (data.startDate !== undefined) {
      await this.startDateInput.fill(data.startDate);
    }
    if (data.endDate !== undefined) {
      await this.endDateInput.fill(data.endDate);
    }
  }

  /**
   * Submit the create review form
   */
  async submitCreateReview() {
    await this.createReviewSubmitButton.click();
    await this.createReviewDialogTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Create a new access review
   */
  async createReview(data: {
    name: string;
    description?: string;
    type?: string;
    startDate?: string;
    endDate?: string;
  }) {
    await this.openCreateReviewModal();
    await this.fillReviewForm(data);
    await this.submitCreateReview();
  }

  /**
   * Get count of visible review rows
   */
  async getReviewCount(): Promise<number> {
    return await this.reviewRows.count();
  }

  /**
   * Find review row by name
   */
  async getReviewRow(name: string): Promise<Locator> {
    return this.page.locator('tr').filter({ hasText: name });
  }

  /**
   * Get review status badge text
   */
  async getReviewStatus(name: string): Promise<string | null> {
    const row = await this.getReviewRow(name);
    const statusBadge = row.locator('[class*="badge"], [class*="Badge"], span[class*="rounded-full"]');
    if (await statusBadge.isVisible().catch(() => false)) {
      return await statusBadge.textContent();
    }
    return null;
  }

  /**
   * Get review progress (reviewed/total items)
   */
  async getReviewProgress(name: string): Promise<{ reviewed: number; total: number; percentage: number } | null> {
    const row = await this.getReviewRow(name);
    const progressText = await row.locator('text=/\\d+\\/\\d+/').textContent();
    if (progressText) {
      const match = progressText.match(/(\d+)\/(\d+)/);
      if (match) {
        const reviewed = parseInt(match[1], 10);
        const total = parseInt(match[2], 10);
        const percentage = total > 0 ? Math.round((reviewed / total) * 100) : 0;
        return { reviewed, total, percentage };
      }
    }
    return null;
  }

  /**
   * Click action menu for a review
   */
  async openReviewActions(name: string) {
    const row = await this.getReviewRow(name);
    await row.locator('button').last().click();
  }

  /**
   * Click View Details for a review
   */
  async viewReviewDetails(name: string) {
    await this.openReviewActions(name);
    await this.page.getByRole('menuitem', { name: /view details/i }).click();
  }

  /**
   * Click Start Review for a pending review
   */
  async startReview(name: string) {
    await this.openReviewActions(name);
    await this.page.getByRole('menuitem', { name: /start review/i }).click();
  }

  /**
   * Get pending reviews count from stats card
   */
  async getPendingCount(): Promise<number> {
    const card = this.page.locator('.grid > div').filter({ hasText: /pending/i });
    const text = await card.locator('.text-2xl').textContent();
    return parseInt(text?.replace(/,/g, '') || '0', 10);
  }

  /**
   * Get in-progress reviews count from stats card
   */
  async getInProgressCount(): Promise<number> {
    const card = this.page.locator('.grid > div').filter({ hasText: /in progress/i });
    const text = await card.locator('.text-2xl').textContent();
    return parseInt(text?.replace(/,/g, '') || '0', 10);
  }

  /**
   * Get completed reviews count from stats card
   */
  async getCompletedCount(): Promise<number> {
    const card = this.page.locator('.grid > div').filter({ hasText: /completed/i });
    const text = await card.locator('.text-2xl').textContent();
    return parseInt(text?.replace(/,/g, '') || '0', 10);
  }

  /**
   * Check if "No access reviews found" message is displayed
   */
  async isNoReviewsMessageVisible(): Promise<boolean> {
    return await this.noReviewsMessage.isVisible().catch(() => false);
  }

  /**
   * Navigate to review detail page
   */
  async navigateToReview(reviewId: string) {
    await this.page.goto(`${this.path}/${reviewId}`);
  }
}
