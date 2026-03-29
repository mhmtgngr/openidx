import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Page Object Model for the Users page
 */
export class UsersPage extends BasePage {
  readonly path = '/users';
  readonly pageTitle: Locator;
  readonly pageDescription: Locator;
  readonly addUserButton: Locator;
  readonly exportCSVButton: Locator;
  readonly importCSVButton: Locator;
  readonly searchInput: Locator;
  readonly usersTable: Locator;
  readonly userRows: Locator;
  readonly noUsersMessage: Locator;
  readonly addUserDialogTitle: Locator;
  readonly usernameInput: Locator;
  readonly emailInput: Locator;
  readonly firstNameInput: Locator;
  readonly lastNameInput: Locator;
  readonly createUserButton: Locator;
  readonly cancelButton: Locator;
  readonly editUserDialogTitle: Locator;
  readonly updateUserButton: Locator;
  readonly importDialogTitle: Locator;
  readonly csvFileInput: Locator;
  readonly importModalButton: Locator;
  readonly deleteConfirmationTitle: Locator;
  readonly deleteConfirmButton: Locator;
  readonly resetPasswordConfirmationTitle: Locator;
  readonly resetPasswordConfirmButton: Locator;

  constructor(page: Page) {
    super(page);
    this.pageTitle = page.getByRole('heading', { name: 'Users', exact: true });
    this.pageDescription = page.locator('text=Manage user accounts and access');
    this.addUserButton = page.getByRole('button', { name: /add user/i });
    this.exportCSVButton = page.getByRole('button', { name: /export csv/i });
    this.importCSVButton = page.getByRole('button', { name: /import csv/i });
    this.searchInput = page.getByPlaceholder(/search users/i);
    this.usersTable = page.locator('table').filter({ has: page.locator('thead') });
    this.userRows = page.locator('tr').filter({ has: page.locator('td') });
    this.noUsersMessage = page.locator('text=/no users found/i');
    this.addUserDialogTitle = page.getByRole('heading', { name: /add new user/i });
    this.usernameInput = page.locator('input[name="username"], input[id="username"]');
    this.emailInput = page.locator('input[name="email"], input[id="email"]');
    this.firstNameInput = page.locator('input[name="first_name"], input[id="first_name"]');
    this.lastNameInput = page.locator('input[name="last_name"], input[id="last_name"]');
    this.createUserButton = page.getByRole('button', { name: /create user/i });
    this.cancelButton = page.getByRole('button', { name: /^cancel$/i });
    this.editUserDialogTitle = page.getByRole('heading', { name: /edit user/i });
    this.updateUserButton = page.getByRole('button', { name: /update user/i });
    this.importDialogTitle = page.getByRole('heading', { name: /import users from csv/i });
    this.csvFileInput = page.locator('input[type="file"]');
    this.importModalButton = page.getByRole('button', { name: /^import$/i });
    this.deleteConfirmationTitle = page.getByRole('heading', { name: /are you sure/i });
    this.deleteConfirmButton = page.getByRole('button', { name: /delete$/i });
    this.resetPasswordConfirmationTitle = page.getByRole('heading', { name: /are you sure/i });
    this.resetPasswordConfirmButton = page.getByRole('button', { name: /reset password/i });
  }

  /**
   * Navigate to the users page
   */
  async goto() {
    await this.page.goto(this.path);
    await this.waitForLoaded();
    await this.pageTitle.waitFor({ state: 'visible' });
  }

  /**
   * Search for users by keyword
   */
  async search(query: string) {
    await this.searchInput.fill(query);
    await this.page.waitForTimeout(300); // Wait for debounced search
  }

  /**
   * Clear search input
   */
  async clearSearch() {
    await this.searchInput.clear();
    await this.page.waitForTimeout(300);
  }

  /**
   * Click Add User button to open the modal
   */
  async openAddUserModal() {
    await this.addUserButton.click();
    await this.addUserDialogTitle.waitFor({ state: 'visible' });
  }

  /**
   * Fill in the add user form
   */
  async fillUserForm(data: { username: string; email: string; firstName?: string; lastName?: string }) {
    await this.usernameInput.fill(data.username);
    await this.emailInput.fill(data.email);
    if (data.firstName !== undefined) await this.firstNameInput.fill(data.firstName);
    if (data.lastName !== undefined) await this.lastNameInput.fill(data.lastName);
  }

  /**
   * Submit the create user form
   */
  async submitCreateUser() {
    await this.createUserButton.click();
  }

  /**
   * Create a new user (opens modal, fills form, submits)
   */
  async createUser(data: { username: string; email: string; firstName?: string; lastName?: string }) {
    await this.openAddUserModal();
    await this.fillUserForm(data);
    await this.submitCreateUser();
    await this.addUserDialogTitle.waitFor({ state: 'hidden', timeout: 5000 });
  }

  /**
   * Get count of visible user rows
   */
  async getUserCount(): Promise<number> {
    return await this.userRows.count();
  }

  /**
   * Find user row by username
   */
  async getUserRow(username: string): Promise<Locator> {
    return this.page.locator('tr').filter({ hasText: username });
  }

  /**
   * Click action menu for a user
   */
  async openUserActions(username: string) {
    const row = await this.getUserRow(username);
    await row.locator('button').last().click();
  }

  /**
   * Click Edit User action for a user
   */
  async editUser(username: string) {
    await this.openUserActions(username);
    await this.page.getByRole('menuitem', { name: /edit user/i }).click();
    await this.editUserDialogTitle.waitFor({ state: 'visible' });
  }

  /**
   * Update user information
   */
  async updateUser(data: { username?: string; email?: string; firstName?: string; lastName?: string }) {
    if (data.username !== undefined) await this.usernameInput.fill(data.username);
    if (data.email !== undefined) await this.emailInput.fill(data.email);
    if (data.firstName !== undefined) await this.firstNameInput.fill(data.firstName);
    if (data.lastName !== undefined) await this.lastNameInput.fill(data.lastName);
    await this.updateUserButton.click();
    await this.editUserDialogTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Click Delete User action and confirm
   */
  async deleteUser(username: string) {
    await this.openUserActions(username);
    await this.page.getByRole('menuitem', { name: /delete user/i }).click();
    await this.deleteConfirmationTitle.waitFor({ state: 'visible' });
    await this.deleteConfirmButton.click();
    await this.deleteConfirmationTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Click Reset Password action
   */
  async initiatePasswordReset(username: string) {
    await this.openUserActions(username);
    await this.page.getByRole('menuitem', { name: /reset password/i }).click();
    await this.resetPasswordConfirmationTitle.waitFor({ state: 'visible' });
  }

  /**
   * Confirm password reset
   */
  async confirmPasswordReset() {
    await this.resetPasswordConfirmButton.click();
    await this.resetPasswordConfirmationTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Open Import CSV modal
   */
  async openImportModal() {
    await this.importCSVButton.click();
    await this.importDialogTitle.waitFor({ state: 'visible' });
  }

  /**
   * Select a CSV file for import
   */
  async selectCSVFile(filePath: string) {
    await this.csvFileInput.setInputFiles(filePath);
  }

  /**
   * Submit the import form
   */
  async submitImport() {
    await this.importModalButton.click();
    await this.importDialogTitle.waitFor({ state: 'hidden' });
  }

  /**
   * Get user status badge text
   */
  async getUserStatus(username: string): Promise<string | null> {
    const row = await this.getUserRow(username);
    const statusBadge = row.locator('[class*="badge"], [class*="Badge"]');
    if (await statusBadge.isVisible().catch(() => false)) {
      return await statusBadge.textContent();
    }
    return null;
  }

  /**
   * Check if "No users found" message is displayed
   */
  async isNoUsersMessageVisible(): Promise<boolean> {
    return await this.noUsersMessage.isVisible().catch(() => false);
  }

  /**
   * Click Export CSV button
   */
  async exportCSV() {
    const downloadPromise = this.page.waitForEvent('download');
    await this.exportCSVButton.click();
    return await downloadPromise;
  }

  /**
   * Navigate to next page if pagination exists
   */
  async goToNextPage() {
    const nextButton = this.page.getByRole('button', { name: /next/i });
    if (await nextButton.isEnabled()) {
      await nextButton.click();
    }
  }

  /**
   * Navigate to previous page if pagination exists
   */
  async goToPreviousPage() {
    const prevButton = this.page.getByRole('button', { name: /previous|prev/i });
    if (await prevButton.isEnabled()) {
      await prevButton.click();
    }
  }
}
