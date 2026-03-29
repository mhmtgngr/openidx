import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Page Object Model for the Dashboard page
 */
export class DashboardPage extends BasePage {
  readonly path = '/dashboard';
  readonly pageTitle: Locator;
  readonly pageDescription: Locator;
  readonly statsCards: Locator;
  readonly totalUsersCard: Locator;
  readonly applicationsCard: Locator;
  readonly activeSessionsCard: Locator;
  readonly pendingReviewsCard: Locator;
  readonly securityAlertsSection: Locator;
  readonly recentActivitySection: Locator;
  readonly analyticsSection: Locator;
  readonly zitiNetworkCard: Locator;
  readonly periodButtons: Locator;

  constructor(page: Page) {
    super(page);
    this.pageTitle = page.getByRole('heading', { name: 'Dashboard', exact: true });
    this.pageDescription = page.locator('text=Overview of your identity platform');
    this.statsCards = page.locator('.grid > div').filter({ hasText: /Total Users|Applications|Active Sessions|Pending Reviews/ });
    this.totalUsersCard = page.locator('.grid > div').filter({ hasText: 'Total Users' });
    this.applicationsCard = page.locator('.grid > div').filter({ hasText: 'Applications' });
    this.activeSessionsCard = page.locator('.grid > div').filter({ hasText: 'Active Sessions' });
    this.pendingReviewsCard = page.locator('.grid > div').filter({ hasText: 'Pending Reviews' });
    this.securityAlertsSection = page.getByText('Security Alerts');
    this.recentActivitySection = page.getByText('Recent Activity');
    this.analyticsSection = page.getByText('Analytics');
    this.zitiNetworkCard = page.locator('text=Zero Trust Network');
    this.periodButtons = page.getByRole('button').filter({ hasText: /^7d$|^30d$|^90d$/ });
  }

  /**
   * Navigate to the dashboard page
   */
  async goto() {
    await this.page.goto(this.path);
    await this.waitForLoaded();
    await this.pageTitle.waitFor({ state: 'visible' });
  }

  /**
   * Get the value from a stat card by title
   */
  async getStatValue(title: string): Promise<number> {
    const card = this.page.locator('.grid > div').filter({ hasText: title });
    const valueElement = card.locator('.text-2xl');
    const text = await valueElement.textContent();
    // Parse the number (handles format like "1,234" or "1234")
    return parseInt(text?.replace(/,/g, '') || '0', 10);
  }

  /**
   * Get Total Users stat value
   */
  async getTotalUsers(): Promise<number> {
    return await this.getStatValue('Total Users');
  }

  /**
   * Get Applications stat value
   */
  async getApplications(): Promise<number> {
    return await this.getStatValue('Applications');
  }

  /**
   * Get Active Sessions stat value
   */
  async getActiveSessions(): Promise<number> {
    return await this.getStatValue('Active Sessions');
  }

  /**
   * Get Pending Reviews stat value
   */
  async getPendingReviews(): Promise<number> {
    return await this.getStatValue('Pending Reviews');
  }

  /**
   * Check if security alerts section is visible
   */
  async isSecurityAlertsVisible(): Promise<boolean> {
    return await this.securityAlertsSection.isVisible().catch(() => false);
  }

  /**
   * Check if recent activity section is visible
   */
  async isRecentActivityVisible(): Promise<boolean> {
    return await this.recentActivitySection.isVisible().catch(() => false);
  }

  /**
   * Get recent activity items count
   */
  async getRecentActivityCount(): Promise<number> {
    const items = this.page.locator('[class*="activity"]').locator('> div');
    return await items.count();
  }

  /**
   * Check if Ziti Network card is visible
   */
  async isZitiNetworkVisible(): Promise<boolean> {
    return await this.zitiNetworkCard.isVisible().catch(() => false);
  }

  /**
   * Click on a period button (7d, 30d, 90d)
   */
  async selectPeriod(period: '7d' | '30d' | '90d') {
    await this.periodButtons.filter({ hasText: period }).click();
  }

  /**
   * Check if analytics charts are visible
   */
  async areAnalyticsChartsVisible(): Promise<boolean> {
    const loginChart = this.page.locator('text=Login Activity');
    const riskChart = this.page.locator('text=Risk Distribution');
    return await loginChart.isVisible().catch(() => false) &&
           await riskChart.isVisible().catch(() => false);
  }

  /**
   * Navigate to a linked page by clicking a stat card
   */
  async navigateToViaCard(cardName: 'Total Users' | 'Applications' | 'Active Sessions' | 'Pending Reviews') {
    const card = this.page.locator('.grid > div').filter({ hasText: cardName });
    await card.click();
  }

  /**
   * Check if dashboard is loaded and visible
   */
  async isLoaded(): Promise<boolean> {
    return await this.pageTitle.isVisible().catch(() => false);
  }
}
