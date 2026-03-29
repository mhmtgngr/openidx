import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Page Object Model for the Login page
 */
export class LoginPage extends BasePage {
  readonly path = '/login';
  readonly usernameInput: Locator;
  readonly passwordInput: Locator;
  readonly loginButton: Locator;
  readonly errorMessage: Locator;
  readonly mfaCodeInput: Locator;
  readonly mfaSubmitButton: Locator;
  readonly magicLinkEmailInput: Locator;
  readonly sendMagicLinkButton: Locator;
  readonly forgotPasswordLink: Locator;
  readonly openidxLogo: Locator;
  readonly loginTitle: Locator;

  constructor(page: Page) {
    super(page);
    this.usernameInput = page.locator('input[name="username"], input[id="username"]');
    this.passwordInput = page.locator('input[name="password"], input[id="password"], input[type="password"]');
    this.loginButton = page.getByRole('button', { name: /sign in|login|log in/i });
    this.errorMessage = page.locator('text=/login failed|authentication failed|invalid credentials/i');
    this.mfaCodeInput = page.locator('input[id="mfa-code"], input[placeholder*="code"], input[maxlength="6"]');
    this.mfaSubmitButton = page.getByRole('button', { name: /verify|submit|confirm/i });
    this.magicLinkEmailInput = page.locator('input[placeholder*="email"], input[name="email"]');
    this.sendMagicLinkButton = page.getByRole('button', { name: /send magic link|send link/i });
    this.forgotPasswordLink = page.getByRole('link', { name: /forgot password/i });
    this.openidxLogo = page.locator('text=OpenIDX');
    this.loginTitle = page.getByRole('heading', { name: /sign in|login|welcome back/i });
  }

  /**
   * Navigate to the login page
   */
  async goto() {
    await this.page.goto(this.path);
    await this.waitForLoaded();
  }

  /**
   * Fill in username
   */
  async fillUsername(username: string) {
    await this.usernameInput.fill(username);
  }

  /**
   * Fill in password
   */
  async fillPassword(password: string) {
    await this.passwordInput.fill(password);
  }

  /**
   * Fill in both username and password
   */
  async fillCredentials(username: string, password: string) {
    await this.fillUsername(username);
    await this.fillPassword(password);
  }

  /**
   * Submit the login form
   */
  async submitLogin() {
    await this.loginButton.click();
  }

  /**
   * Complete login flow with credentials
   */
  async login(username: string, password: string) {
    await this.fillCredentials(username, password);
    await this.submitLogin();
  }

  /**
   * Check if login form is visible
   */
  async isLoginFormVisible(): Promise<boolean> {
    return await this.usernameInput.isVisible().catch(() => false);
  }

  /**
   * Check if MFA form is visible
   */
  async isMFAFormVisible(): Promise<boolean> {
    return await this.mfaCodeInput.isVisible().catch(() => false);
  }

  /**
   * Fill in MFA code
   */
  async fillMFACode(code: string) {
    await this.mfaCodeInput.fill(code);
  }

  /**
   * Submit MFA code
   */
  async submitMFA() {
    await this.mfaSubmitButton.click();
  }

  /**
   * Complete MFA flow
   */
  async completeMFA(code: string) {
    await this.fillMFACode(code);
    await this.submitMFA();
  }

  /**
   * Click forgot password link
   */
  async clickForgotPassword() {
    await this.forgotPasswordLink.click();
  }

  /**
   * Get error message text if visible
   */
  async getErrorMessage(): Promise<string | null> {
    if (await this.errorMessage.isVisible()) {
      return await this.errorMessage.textContent();
    }
    return null;
  }

  /**
   * Check if page is showing the login form
   */
  async isOnPage(): Promise<boolean> {
    return await this.loginTitle.isVisible().catch(() => false);
  }

  /**
   * Get the current page title
   */
  async getPageTitle(): Promise<string> {
    return await this.page.title();
  }
}
