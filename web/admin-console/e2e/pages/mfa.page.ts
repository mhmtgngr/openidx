import { Page, Locator } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Page Object Model for MFA (Multi-Factor Authentication) setup
 */
export class MFAPage extends BasePage {
  readonly mfaSetupWizardTitle: Locator;
  readonly totpOptionCard: Locator;
  readonly smsOptionCard: Locator;
  readonly emailOptionCard: Locator;
  readonly webauthnOptionCard: Locator;
  readonly qrCodeContainer: Locator;
  readonly totpCodeInput: Locator;
  readonly verifyAndEnableButton: Locator;
  readonly phoneNumberInput: Locator;
  readonly countryCodeInput: Locator;
  readonly sendCodeButton: Locator;
  readonly backupCodesGrid: Locator;
  readonly copyAllCodesButton: Locator;
  readonly generateBackupCodesButton: Locator;
  readonly skipBackupButton: Locator;
  readonly iveSavedCodesButton: Locator;
  readonly mfaCompleteMessage: Locator;
  readonly doneButton: Locator;
  readonly backButton: Locator;

  constructor(page: Page) {
    super(page);
    this.mfaSetupWizardTitle = page.getByRole('heading', { name: /add authentication method/i });
    this.totpOptionCard = page.locator('div').filter({ hasText: /authenticator app/i });
    this.smsOptionCard = page.locator('div').filter({ hasText: /sms/i }).filter({ hasText: /receive verification codes/i });
    this.emailOptionCard = page.locator('div').filter({ hasText: /email/i }).filter({ hasText: /receive verification codes/i });
    this.webauthnOptionCard = page.locator('div').filter({ hasText: /passkey/i });
    this.qrCodeContainer = page.locator('canvas, svg').locator('xpath=ancestor::div[contains(@class, "bg-white")]');
    this.totpCodeInput = page.locator('input[placeholder*="code"], input[maxlength="6"], input[inputmode="numeric"]');
    this.verifyAndEnableButton = page.getByRole('button', { name: /verify & enable|verify and enable/i });
    this.phoneNumberInput = page.locator('input[id*="phone"], input[name*="phone"]');
    this.countryCodeInput = page.locator('input[id*="country"], input[name*="country"]');
    this.sendCodeButton = page.getByRole('button', { name: /send code/i });
    this.backupCodesGrid = page.locator('.grid').filter({ has: this.page.locator('[class*="font-mono"]') });
    this.copyAllCodesButton = page.getByRole('button', { name: /copy all codes/i });
    this.generateBackupCodesButton = page.getByRole('button', { name: /generate backup codes/i });
    this.skipBackupButton = page.getByRole('button', { name: /skip for now/i });
    this.iveSavedCodesButton = page.getByRole('button', { name: /i've saved my backup codes/i });
    this.mfaCompleteMessage = page.getByText('MFA Setup Complete');
    this.doneButton = page.getByRole('button', { name: /done$/i });
    this.backButton = page.getByRole('button', { name: /^back$/i });
  }

  /**
   * Select TOTP (Authenticator App) as MFA method
   */
  async selectTOTPMethod() {
    await this.totpOptionCard.click();
    await this.qrCodeContainer.waitFor({ state: 'visible' });
  }

  /**
   * Select SMS as MFA method
   */
  async selectSMSMethod() {
    await this.smsOptionCard.click();
  }

  /**
   * Select Email as MFA method
   */
  async selectEmailMethod() {
    await this.emailOptionCard.click();
  }

  /**
   * Select WebAuthn/Passkey as MFA method
   */
  async selectWebAuthnMethod() {
    await this.webauthnOptionCard.click();
  }

  /**
   * Fill in TOTP verification code
   */
  async fillTOTPCode(code: string) {
    await this.totpCodeInput.fill(code);
  }

  /**
   * Verify and enable TOTP
   */
  async verifyTOTP(code: string) {
    await this.fillTOTPCode(code);
    await this.verifyAndEnableButton.click();
  }

  /**
   * Get QR code URL (for testing purposes - in real tests you'd generate a valid code)
   */
  async getQRCodeVisible(): Promise<boolean> {
    return await this.qrCodeContainer.isVisible().catch(() => false);
  }

  /**
   * Fill in phone number for SMS setup
   */
  async fillPhoneNumber(phoneNumber: string, countryCode: string = '+1') {
    await this.countryCodeInput.fill(countryCode);
    await this.phoneNumberInput.fill(phoneNumber);
  }

  /**
   * Send SMS verification code
   */
  async sendSMSCode() {
    await this.sendCodeButton.click();
  }

  /**
   * Click Generate Backup Codes button
   */
  async generateBackupCodes() {
    await this.generateBackupCodesButton.click();
  }

  /**
   * Get all backup codes displayed
   */
  async getBackupCodes(): Promise<string[]> {
    const codes = this.page.locator('[class*="font-mono"]');
    const count = await codes.count();
    const result: string[] = [];
    for (let i = 0; i < count; i++) {
      const text = await codes.nth(i).textContent();
      if (text) result.push(text);
    }
    return result;
  }

  /**
   * Click "I've Saved My Backup Codes" to proceed
   */
  async confirmBackupCodesSaved() {
    await this.iveSavedCodesButton.click();
  }

  /**
   * Skip backup codes step
   */
  async skipBackupCodes() {
    await this.skipBackupButton.click();
  }

  /**
   * Click Done to complete MFA setup
   */
  async clickDone() {
    await this.doneButton.click();
  }

  /**
   * Check if MFA setup completion message is visible
   */
  async isMFAComplete(): Promise<boolean> {
    return await this.mfaCompleteMessage.isVisible().catch(() => false);
  }

  /**
   * Click back button in wizard
   */
  async clickBack() {
    await this.backButton.click();
  }

  /**
   * Complete TOTP MFA setup flow
   */
  async setupTOTP(code: string, generateBackup: boolean = false) {
    await this.selectTOTPMethod();
    await this.verifyTOTP(code);

    if (generateBackup) {
      await this.generateBackupCodes();
      await this.confirmBackupCodesSaved();
    } else {
      await this.skipBackupCodes();
    }

    await this.clickDone();
  }
}
